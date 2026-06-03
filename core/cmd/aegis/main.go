package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aegis-ai/aegis/internal/mcp"
	"github.com/aegis-ai/aegis/internal/policy"
	"github.com/aegis-ai/aegis/internal/proxy"
	"github.com/aegis-ai/aegis/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: aegis <serve|proxy> [flags]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "proxy":
		runProxy(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr        := fs.String("addr",         envOr("AEGIS_ADDR", ":8080"), "listen address")
	dbURL       := fs.String("db",           os.Getenv("DATABASE_URL"),    "postgres connection string")
	apiKey      := fs.String("key",          os.Getenv("AEGIS_API_KEY"),   "api key (X-Aegis-Key)")
	cfgPath     := fs.String("config",       "aegis.config.yaml",          "path to policy config")
	behindProxy := fs.Bool("behind-proxy",   false,                         "set when a TLS-terminating reverse proxy is in front of aegis")
	sessionTTL  := fs.Duration("session-ttl", 24*time.Hour,                "how long to keep idle sessions")
	_ = fs.Parse(args)

	requireNonEmpty("DATABASE_URL / --db", *dbURL)
	requireNonEmpty("AEGIS_API_KEY / --key", *apiKey)
	warnWeakKey(*apiKey)

	// Refuse to bind on a non-loopback address without an explicit acknowledgement
	// that a TLS-terminating proxy is in front. Passing --behind-proxy opts in.
	if !*behindProxy && !isLoopback(*addr) {
		log.Fatal("aegis is about to listen on a non-loopback address over plain HTTP.\n" +
			"Put a TLS-terminating reverse proxy (nginx, caddy, etc.) in front and\n" +
			"restart with --behind-proxy to acknowledge this.")
	}

	cfg, db := bootstrap(*cfgPath, *dbURL)
	defer db.Close()

	srv := proxy.NewServer(*addr, *apiKey, cfg, db, *behindProxy)
	slog.Info("aegis serve", "addr", *addr)
	if !*behindProxy {
		slog.Warn("serving over plain http — put a TLS-terminating proxy in front for production")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// prune expired sessions on a background ticker
	go runPruner(ctx, db, *sessionTTL)

	if err := srv.Start(ctx); err != nil {
		log.Fatal(err)
	}
}

func runProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	upstream := fs.String("upstream", "",                                 "upstream mcp server url")
	port     := fs.String("port",     envOr("AEGIS_PROXY_PORT", "4000"), "listen port")
	dbURL    := fs.String("db",       os.Getenv("DATABASE_URL"),         "postgres connection string")
	apiKey   := fs.String("key",      os.Getenv("AEGIS_API_KEY"),        "api key (X-Aegis-Key)")
	cfgPath  := fs.String("config",   "aegis.config.yaml",               "path to policy config")
	_ = fs.Parse(args)

	requireNonEmpty("--upstream", *upstream)
	requireNonEmpty("DATABASE_URL / --db", *dbURL)
	requireNonEmpty("AEGIS_API_KEY / --key", *apiKey)

	cfg, db := bootstrap(*cfgPath, *dbURL)
	defer db.Close()

	p, err := mcp.NewProxy(*upstream, *apiKey, db, policy.NewEvaluator(cfg))
	if err != nil {
		log.Fatalf("create mcp proxy: %v", err)
	}

	addr := ":" + *port
	slog.Info("aegis proxy", "addr", addr, "upstream", *upstream)
	runUntilSignal(func(ctx context.Context) error {
		return p.ListenAndServe(ctx, addr)
	})
}

func bootstrap(cfgPath, dbURL string) (*policy.Config, *store.Store) {
	cfg, err := policy.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	ctx := context.Background()
	db, err := store.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("connect db: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	return cfg, db
}

// runPruner deletes sessions older than ttl every hour.
func runPruner(ctx context.Context, db *store.Store, ttl time.Duration) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := db.PruneExpiredSessions(ctx, ttl)
			if err != nil {
				slog.Error("prune sessions", "err", err)
			} else if n > 0 {
				slog.Info("pruned sessions", "count", n)
			}
		}
	}
}

func runUntilSignal(fn func(context.Context) error) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := fn(ctx); err != nil {
		log.Fatal(err)
	}
}

func requireNonEmpty(name, val string) {
	if val == "" {
		log.Fatalf("%s is required", name)
	}
}

// warnWeakKey logs a warning when the API key is obviously too short or
// matches a known insecure default value.
func warnWeakKey(key string) {
	weakDefaults := []string{"dev-key", "changeme", "test", "secret", "password", "aegis"}
	if len(key) < 32 {
		slog.Warn("AEGIS_API_KEY is shorter than 32 characters — use a strong random key in production (e.g. openssl rand -hex 32)")
	}
	lower := strings.ToLower(key)
	for _, w := range weakDefaults {
		if lower == w {
			slog.Warn("AEGIS_API_KEY matches a known insecure default — replace it before exposing this service", "key", key)
			return
		}
	}
}

// isLoopback reports whether addr is bound to a loopback interface only.
func isLoopback(addr string) bool {
	loopbacks := []string{"127.", "localhost:", "[::1]"}
	for _, prefix := range loopbacks {
		if strings.HasPrefix(addr, prefix) {
			return true
		}
	}
	return false
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
