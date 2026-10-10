package server

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// HTTPSRedirectListener routes accidental plaintext requests to HTTPS before
// TLS parses them. Detection runs in each HTTP server connection goroutine,
// with the server's handshake deadlines; Accept never waits for client bytes.
func HTTPSRedirectListener(listener net.Listener, publicHost string) net.Listener {
	return &httpsRedirectListener{Listener: listener, publicHost: publicHost}
}

type httpsRedirectListener struct {
	net.Listener
	publicHost string
}

func (l *httpsRedirectListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &httpsRedirectConn{Conn: conn, reader: bufio.NewReader(conn), publicHost: l.publicHost}, nil
}

type httpsRedirectConn struct {
	net.Conn
	reader     *bufio.Reader
	publicHost string
	detected   bool
}

func (c *httpsRedirectConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.detected {
		c.detected = true
		header, err := c.reader.Peek(5)
		if err != nil {
			return 0, err
		}
		if plaintextHTTP(header) {
			c.redirectHTTP()
			return 0, io.EOF
		}
	}
	return c.reader.Read(p)
}

func plaintextHTTP(header []byte) bool {
	for _, method := range []string{"GET ", "HEAD ", "POST ", "PUT ", "DELET", "OPTIO", "PATCH", "TRACE", "CONNE"} {
		if strings.HasPrefix(string(header), method) {
			return true
		}
	}
	return false
}

func (c *httpsRedirectConn) redirectHTTP() {
	// A client cannot force unbounded header buffering. Never pass a plaintext
	// request to the application, inspect its body or trust its Host header.
	request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(c.reader, 16<<10)))
	if err != nil {
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		_, _ = io.WriteString(c.Conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 10\r\nContent-Type: text/plain\r\n\r\nUse HTTPS\n")
		return
	}
	authority := c.LocalAddr().String()
	if c.publicHost != "" {
		_, port, err := net.SplitHostPort(authority)
		if err != nil {
			return
		}
		authority = net.JoinHostPort(c.publicHost, port)
	}
	location := (&url.URL{Scheme: "https", Host: authority, Path: request.URL.Path, RawPath: request.URL.RawPath, RawQuery: request.URL.RawQuery}).String()
	_, _ = fmt.Fprintf(c.Conn, "HTTP/1.1 308 Permanent Redirect\r\nLocation: %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", location)
}

// QuietHTTPErrorLogger drops only routine disconnects during TLS negotiation.
// Malformed TLS, certificate errors, HTTP handler panics and other failures
// retain their original details and remain visible in the service journal.
func QuietHTTPErrorLogger(destination *log.Logger) *log.Logger {
	return log.New(httpErrorWriter{destination}, "", 0)
}

type httpErrorWriter struct{ destination *log.Logger }

func (w httpErrorWriter) Write(raw []byte) (int, error) {
	message := strings.TrimSpace(string(raw))
	if strings.HasPrefix(message, "http: TLS handshake error from ") &&
		(strings.HasSuffix(message, ": EOF") || strings.HasSuffix(message, ": unexpected EOF")) {
		return len(raw), nil
	}
	w.destination.Print(message)
	return len(raw), nil
}
