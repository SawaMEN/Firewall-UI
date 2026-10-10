package server

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPSRedirectAndTLSRemainIsolated(t *testing.T) {
	handled := make(chan struct{}, 4)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("plaintext request reached authenticated application")
		}
		handled <- struct{}{}
		io.WriteString(w, "secure panel")
	}))
	s.Listener = HTTPSRedirectListener(s.Listener, "panel.example.com")
	s.Config.ErrorLog = QuietHTTPErrorLogger(log.New(io.Discard, "", 0))
	s.Config.ReadHeaderTimeout = time.Second
	s.StartTLS()
	defer s.Close()
	address := s.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, _ := http.NewRequest(http.MethodGet, "http://"+address+"/settings?tab=https", nil)
	request.Host = "attacker.example"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusPermanentRedirect || response.Header.Get("Location") != "https://panel.example.com:"+port+"/settings?tab=https" {
		t.Fatalf("incorrect HTTPS redirect: %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	response, err = client.Post("http://"+address+"/api/login", "application/json", strings.NewReader(`{"password":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("plaintext credentials were accepted: %d", response.StatusCode)
	}
	select {
	case <-handled:
		t.Fatal("plaintext request reached panel")
	default:
	}
	// A slow plaintext client cannot block Accept or other TLS clients.
	slow, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	slow.Write([]byte("G"))
	response, err = s.Client().Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(raw) != "secure panel" {
		t.Fatalf("TLS panel changed: %s", raw)
	}
}

func TestHTTPErrorLoggerPreservesRealFailures(t *testing.T) {
	var output bytes.Buffer
	logger := QuietHTTPErrorLogger(log.New(&output, "", 0))
	for _, message := range []string{
		"http: TLS handshake error from 127.0.0.1:1: EOF",
		"http: TLS handshake error from 127.0.0.1:1: unexpected EOF",
	} {
		logger.Print(message)
	}
	if output.Len() != 0 {
		t.Fatalf("routine disconnect logged: %s", output.String())
	}
	for _, message := range []string{
		"http: TLS handshake error from 127.0.0.1:1: local error: tls: error decoding message",
		"http: TLS handshake error from 127.0.0.1:1: remote error: tls: bad certificate",
		"http: panic serving 127.0.0.1:1: EOF",
	} {
		logger.Print(message)
		if !strings.Contains(output.String(), message) {
			t.Fatalf("real failure was hidden: %s", message)
		}
	}
}

func TestHTTPSRedirectIPv6Authority(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	// The actual bound endpoint, rather than the client's Host, is the fallback.
	conn := &httpsRedirectConn{Conn: &localAddrConn{Conn: server}, reader: nil, publicHost: "2001:db8::1"}
	conn.reader = bufio.NewReader(server)
	done := make(chan struct{})
	go func() { defer close(done); conn.Read(make([]byte, 5)) }()
	client.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(client, "GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.Header.Get("Location") != "https://[2001:db8::1]:8443/" {
		t.Fatalf("invalid IPv6 authority: %s", response.Header.Get("Location"))
	}
	<-done
}

type localAddrConn struct{ net.Conn }

func (*localAddrConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("::1"), Port: 8443} }
