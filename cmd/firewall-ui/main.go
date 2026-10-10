package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	saveConfig := flag.Bool("save-config", false, "Save configuration overrides and exit")
	publicHostFlag := flag.String("public-host", "", "External domain or IP (overrides config)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	cleanupFirewall := flag.Bool("cleanup-firewall", false, "Remove only Firewall-UI-owned firewall rules and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.Current().Version)
		return
	}

	if *cleanupFirewall {
		if os.Geteuid() != 0 {
			log.Fatal("Firewall cleanup requires root")
		}
		// Cleanup must remain available when an installed certificate has expired
		// or been removed. Only the state location is needed; do not start HTTP.
		cfg := appconfig.Default()
		raw, err := os.ReadFile(*configPath)
		if err != nil && !os.IsNotExist(err) {
			log.Fatal(err)
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &cfg); err != nil {
				log.Fatal(err)
			}
		}
		if !filepath.IsAbs(cfg.StatePath) {
			log.Fatal("State path must be absolute")
		}
		service.Configure(cfg.StatePath, cfg.ListenPort, cfg.ExternalPort)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := (&service.FirewallService{}).CleanupOwnedRules(ctx); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Firewall-UI rules removed")
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

	if visited["public-host"] {
		cfg.PublicHost = strings.TrimSpace(*publicHostFlag)
	}
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

	if *saveConfig {
		if err := appconfig.Save(*configPath, cfg); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Configuration saved")
		return
	}
	if *checkConfig {
		fmt.Println("Configuration is valid")
		return
	}
	containerMode := os.Getenv("FIREWALL_UI_CONTAINER") == "1"
	user := strings.TrimSpace(os.Getenv("FIREWALL_UI_USERNAME"))
	password := os.Getenv("FIREWALL_UI_PASSWORD")
	if containerMode {
		user, password, err = appconfig.ContainerCredentials(filepath.Join(filepath.Dir(*configPath), "environment"), user, password)
		if err != nil {
			log.Fatal(err)
		}
	}
	if password == "" {
		log.Fatal("FIREWALL_UI_PASSWORD must not be empty")
	}
	if len(password) < 12 {
		log.Print("Recommendation: use a long unique password")
	}
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
	if !containerMode {
		app.Updater = updateManager
	}
	dataDir := filepath.Dir(cfg.StatePath)
	app.Audit = audit.New(filepath.Join(dataDir, "audit.jsonl"))
	app.History = history.New(filepath.Join(dataDir, "history.jsonl"))
	portMonitor := service.NewPortMonitor("/proc", time.Duration(cfg.PortScanInterval)*time.Second)
	app.PortMonitor = portMonitor
	app.Firewall.StartAutoSync()

	srv := &http.Server{
		Addr:              cfg.Address(),
		Handler:           app,
		ErrorLog:          server.QuietHTTPErrorLogger(log.Default()),
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
	if !containerMode {
		go updateManager.Run(ctx, *configPath)
	}
	go func() {
		<-ctx.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(deadline)
	}()

	info := buildinfo.Current()
	log.Printf("Firewall-UI %s (%s, %s) listening on %s (user %s)", info.Version, info.Channel, info.Commit, cfg.Address(), user)
	if cfg.TLSCert != "" {
		listener, listenErr := net.Listen("tcp", cfg.Address())
		if listenErr != nil {
			err = listenErr
		} else {
			err = srv.ServeTLS(server.HTTPSRedirectListener(listener, cfg.PublicHost), cfg.TLSCert, cfg.TLSKey)
		}
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
