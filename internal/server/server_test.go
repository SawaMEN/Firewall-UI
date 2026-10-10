package server

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestSessionAndCSRF(t *testing.T) {
	var assets fs.FS = fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ui")}}
	s := New("admin", "long-test-password", 8088, assets)
	send := func(method, path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.RemoteAddr = "127.0.0.1:12345"
		if cookie != nil {
			r.AddCookie(cookie)
		}
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if w := send("GET", "/api/ports", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := send("POST", "/api/login", `{"username":"admin","password":"long-test-password"}`, "", nil)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("login failed: %s", w.Body)
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	var result struct {
		Obj struct {
			CSRF string `json:"csrf"`
		} `json:"obj"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if w := send("POST", "/api/logout", "{}", "", cookie); w.Code != 403 {
		t.Fatal("accepted missing CSRF")
	}
	if w := send("GET", "/api/session", "", "", cookie); w.Code != 200 {
		t.Fatal("session missing")
	}
	if w := send("POST", "/panel/api/server/firewall/enabled", "{}", result.Obj.CSRF, cookie); w.Code != 400 {
		t.Fatal("accepted missing enabled")
	}
	if w := send("POST", "/api/logout", "{}", result.Obj.CSRF, cookie); w.Code != 200 {
		t.Fatal("logout failed")
	}
	if w := send("GET", "/api/session", "", "", cookie); w.Code != 401 {
		t.Fatal("logout did not revoke session")
	}
}
func TestLoginRateLimit(t *testing.T) {
	s := New("admin", "long-test-password", 8088, fstest.MapFS{})
	for i := 0; i < 6; i++ {
		r := httptest.NewRequest("POST", "/api/login", bytes.NewBufferString(`{"username":"admin","password":"wrong"}`))
		r.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		expected := 401
		if i == 5 {
			expected = 429
		}
		if w.Code != expected {
			t.Fatalf("attempt %d: got %d", i, w.Code)
		}
		if expected == 429 && w.Header().Get("Retry-After") == "" {
			t.Fatal("rate limit response has no Retry-After header")
		}
	}
}
func TestCrossSiteLogin(t *testing.T) {
	s := New("admin", "long-test-password", 8088, fstest.MapFS{})
	r := httptest.NewRequest("POST", "/api/login", bytes.NewBufferString(`{"username":"admin","password":"long-test-password"}`))
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-site login accepted")
	}
}

func TestRootAndSPAAssets(t *testing.T) {
	s := New("admin", "test-password", 8088, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("panel page")}, "assets/app.js": &fstest.MapFile{Data: []byte("script")}})
	for _, path := range []string{"/", "/settings", "/index.html", "/assets/app.js"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || w.Header().Get("Location") != "" {
			t.Fatalf("%s redirects or fails: %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/assets/missing.js", nil))
	if w.Code != 404 {
		t.Fatal("missing asset became HTML")
	}
}

func TestHTTPSAndHTTPLoginCookiesCoexist(t *testing.T) {
	tlsApp := New("admin", "1", 8088, fstest.MapFS{})
	tlsServer := httptest.NewTLSServer(tlsApp)
	defer tlsServer.Close()
	httpServer := httptest.NewServer(New("admin", "1", 8088, fstest.MapFS{}))
	defer httpServer.Close()
	client := tlsServer.Client()
	client.Jar, _ = cookiejar.New(nil)
	for _, base := range []string{tlsServer.URL, httpServer.URL, tlsServer.URL, httpServer.URL} {
		response, err := client.Post(base+"/api/login", "application/json", bytes.NewBufferString(`{"username":"admin","password":"1"}`))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("login: %d", response.StatusCode)
		}
		response, err = client.Get(base + "/api/session")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("cookie not returned: %d", response.StatusCode)
		}
	}
	if New("admin", "1", 8088, fstest.MapFS{}).sessionCookieName(httptest.NewRequest("GET", "/", nil)) == New("admin", "1", 8089, fstest.MapFS{}).sessionCookieName(httptest.NewRequest("GET", "/", nil)) {
		t.Fatal("different panel ports share a cookie name")
	}
}
