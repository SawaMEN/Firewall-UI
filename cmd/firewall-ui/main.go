package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
	"github.com/SawaMEN/Firewall-UI/internal/audit"
	"github.com/SawaMEN/Firewall-UI/internal/buildinfo"
	"github.com/SawaMEN/Firewall-UI/internal/history"
	"github.com/SawaMEN/Firewall-UI/internal/server"
	"github.com/SawaMEN/Firewall-UI/internal/service"
	"github.com/SawaMEN/Firewall-UI/internal/updater"
	"github.com/SawaMEN/Firewall-UI/internal/webassets"
)

func main() {
	configPath := flag.String("config", "/etc/firewall-ui/config.json", "Runtime configuration file")
	listenFlag := flag.String("listen", "", "HTTP listen address (overrides config)")
	stateFlag := flag.String("state", "", "Persistent settings file (overrides config)")
	externalFlag := flag.Int("external-port", -1, "Reverse proxy public port to protect (overrides config)")
	certFlag := flag.String("tls-cert", "", "TLS certificate path (overrides config)")
	keyFlag := flag.String("tls-key", "", "TLS key path (overrides config)")
	secureFlag := flag.Bool("secure-cookies", false, "Require HTTPS cookies behind a reverse proxy (overrides config)")
	checkConfig := flag.Bool("check-config", false, "Validate panel configuration and exit")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.Current().Version)
		return
	}

	cfg, err := appconfig.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	visited := map[string]bool{}
	flag.CommandLine.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})

	if visited["listen"] {
		host, rawPort, err := net.SplitHostPort(*listenFlag)
		if err != nil {
			log.Fatal(err)
		}
		port, err := strconv.Atoi(rawPort)
		if err != nil {
			log.Fatal("invalid listen port")
		}
		cfg.ListenHost = host
		cfg.ListenPort = port
	}
	if visited["state"] {
		cfg.StatePath = *stateFlag
	}
	if visited["external-port"] {
		cfg.ExternalPort = *externalFlag
	}
	if visited["tls-cert"] {
		cfg.TLSCert = *certFlag
	}
	if visited["tls-key"] {
		cfg.TLSKey = *keyFlag
	}
	if visited["secure-cookies"] {
		cfg.SecureCookies = *secureFlag
	}
	if err := appconfig.Validate(cfg); err != nil {
		log.Fatal(err)
	}

	if *checkConfig {
		fmt.Println("Configuration is valid")
		return
	}
	password := os.Getenv("FIREWALL_UI_PASSWORD")
	if len(password) < 12 {
		log.Fatal("FIREWALL_UI_PASSWORD must contain at least 12 characters")
	}
	user := strings.TrimSpace(os.Getenv("FIREWALL_UI_USERNAME"))
	if user == "" {
		user = "admin"
	}
	if os.Geteuid() != 0 {
		log.Print("Run as root to manage the firewall and see all process owners")
	}

	service.Configure(cfg.StatePath, cfg.ListenPort, cfg.ExternalPort)
	assets, _ := fs.Sub(webassets.Files, "dist")
	app := server.New(user, password, cfg.ListenPort, assets)
	app.SecureCookies = cfg.SecureCookies
	app.ConfigPath = *configPath
	app.RuntimeConfig = cfg
	app.Restart = func() {
		process, findErr := os.FindProcess(os.Getpid())
		if findErr == nil {
			_ = process.Signal(syscall.SIGTERM)
		}
	}
	updateManager := updater.New(app.Restart)
	app.Updater = updateManager
	dataDir := filepath.Dir(cfg.StatePath)
	app.Audit = audit.New(filepath.Join(dataDir, "audit.jsonl"))
	app.History = history.New(filepath.Join(dataDir, "history.jsonl"))
	portMonitor := service.NewPortMonitor("/proc", time.Duration(cfg.PortScanInterval)*time.Second)
	app.PortMonitor = portMonitor
	app.Firewall.StartAutoSync()

	srv := &http.Server{
		Addr:              cfg.Address(),
		Handler:           app,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      6 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16384,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	portMonitor.Start(ctx)
	go updateManager.Run(ctx, *configPath)
	go func() {
		<-ctx.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(deadline)
	}()

	info := buildinfo.Current()
	log.Printf("Firewall-UI %s (%s, %s) listening on %s (user %s)", info.Version, info.Channel, info.Commit, cfg.Address(), user)
	if cfg.TLSCert != "" {
		err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
