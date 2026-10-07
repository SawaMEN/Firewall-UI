package main

import (
	"context"
	"crypto/tls"
	"flag"
	"github.com/SawaMEN/Firewall-UI/internal/server"
	"github.com/SawaMEN/Firewall-UI/internal/service"
	"github.com/SawaMEN/Firewall-UI/internal/webassets"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8088", "HTTP listen address")
	state := flag.String("state", "/var/lib/firewall-ui/state.json", "Persistent settings file")
	external := flag.Int("external-port", 0, "Reverse proxy public port to protect")
	cert := flag.String("tls-cert", "", "TLS certificate path")
	key := flag.String("tls-key", "", "TLS key path")
	secureCookies := flag.Bool("secure-cookies", false, "Require HTTPS cookies behind a reverse proxy")
	flag.Parse()
	password := os.Getenv("FIREWALL_UI_PASSWORD")
	if len(password) < 12 {
		log.Fatal("FIREWALL_UI_PASSWORD must contain at least 12 characters")
	}
	user := os.Getenv("FIREWALL_UI_USERNAME")
	if user == "" {
		user = "admin"
	}
	_, raw, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatal(err)
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		log.Fatal("invalid listen port")
	}
	if *external < 0 || *external > 65535 {
		log.Fatal("invalid external port")
	}
	if (*cert == "") != (*key == "") {
		log.Fatal("both TLS certificate and key are required")
	}
	if os.Geteuid() != 0 {
		log.Print("Run as root to manage the firewall and see all process owners")
	}
	service.Configure(*state, port, *external)
	assets, _ := fs.Sub(webassets.Files, "dist")
	app := server.New(user, password, port, assets)
	app.SecureCookies = *secureCookies
	app.Firewall.StartAutoSync()
	srv := &http.Server{Addr: *listen, Handler: app, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 6 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(deadline)
	}()
	log.Printf("Firewall-UI listening on %s (user %s)", *listen, strings.TrimSpace(user))
	if *cert != "" {
		err = srv.ListenAndServeTLS(*cert, *key)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
