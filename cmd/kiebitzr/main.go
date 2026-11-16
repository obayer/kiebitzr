// Command kiebitzr watches the images running in a Kubernetes cluster and exports their
// known vulnerabilities as Prometheus metrics. See docs/adr for the design.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	// Registers the `sqlite` database/sql driver that Syft's RPM cataloger needs (see
	// internal/catalog). It is the same pure-Go driver the vulnerability database already
	// uses, so CGO stays off and the name is registered exactly once.
	_ "github.com/glebarez/go-sqlite"

	"github.com/obayer/kiebitzr/internal/buildaccess"
	"github.com/obayer/kiebitzr/internal/cache"
	"github.com/obayer/kiebitzr/internal/catalog"
	"github.com/obayer/kiebitzr/internal/config"
	"github.com/obayer/kiebitzr/internal/dispatch"
	"github.com/obayer/kiebitzr/internal/kube"
	"github.com/obayer/kiebitzr/internal/metrics"
	"github.com/obayer/kiebitzr/internal/runner"
	"github.com/obayer/kiebitzr/internal/upgrade"
	"github.com/obayer/kiebitzr/internal/version"
	"github.com/obayer/kiebitzr/internal/vulndb"
	"github.com/obayer/kiebitzr/internal/workq"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Before anything touches a registry or the database: Syft, Grype and Stereoscope keep
	// package-level loggers that discard everything until they are set, and they are the
	// part of this service that can actually fail at the network. Each library is wired by
	// the package that owns it, because only those two may import them.
	catalog.SetLogger(log)
	vulndb.SetLogger(log)

	cfg, err := config.Parse(os.Args[1:], os.Stderr)
	switch {
	case errors.Is(err, config.ErrHelp):
		return
	case err != nil:
		log.Error("configuration", "err", err)
		os.Exit(2)
	}

	// A ConfigMap bound with `envFrom` puts all of its keys into the environment, so a
	// misspelled one would change nothing and say nothing. Reported once at start-up, because
	// "the value I set has no effect" is otherwise a long search.
	if unknown := config.UnknownEnvVars(); len(unknown) > 0 {
		log.Warn("ignoring environment variables that match no flag of this build",
			"names", strings.Join(unknown, ","))
	}

	log.Info("starting", "version", version.Version, "commit", version.Commit)

	// Every setting, once, with the value in effect — the line that answers "did my ConfigMap
	// land" without a shell in the pod. It is deliberately not a selection: the three values
	// that used to be here were the ones somebody had needed so far, which is a list that is
	// always one incident behind. A derived value is logged as resolved rather than as given
	// (`catalogue_timeout`), and a credential somebody put in a URL is redacted.
	log.LogAttrs(context.Background(), slog.LevelInfo, "settings", cfg.LogAttrs()...)

	if err := run(cfg, log); err != nil {
		log.Error("exit", "err", err)
		os.Exit(1)
	}
}

// run dispatches on the role. The two share a binary and an image but almost nothing else: a
// worker builds no Kubernetes client, opens no cache and never touches the vulnerability
// database (ADR 0009).
func run(cfg config.Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Role == config.RoleWorker {
		return runWorker(ctx, cfg, log)
	}
	return runMatcher(ctx, cfg, log)
}

// runWorker catalogues images the matcher hands out, and nothing else. It has no cluster
// access at all; the registry credentials are the only secret it holds.
func runWorker(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	// A listener that dies takes the process with it, so the cataloguing loop cannot keep
	// running behind an endpoint nothing can scrape. Without this, a refused port left a
	// worker working away invisibly instead of exiting for Kubernetes to restart.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cataloguer, err := catalog.New(cfg.Platform)
	if err != nil {
		return fmt.Errorf("cataloguer: %w", err)
	}

	// The client timeout has to outlast the matcher's long poll, or every request for work
	// would be cut off before it could answer.
	client, err := dispatch.NewClient(cfg.MatcherURL, dispatch.DefaultPollTimeout+30*time.Second)
	if err != nil {
		return fmt.Errorf("matcher: %w", err)
	}

	// Its own metric set, not the matcher's: a worker serving
	// kiebitzr_last_success_timestamp_seconds would read as a matcher that never finished a
	// run, and the alert for that would fire once per worker.
	exporter := metrics.NewWorker()

	var loop sync.WaitGroup
	loop.Go(func() {
		dispatch.NewWorker(client, cataloguer, exporter, log).Run(ctx)
	})

	err = serve(ctx, cfg.Listen, newMux(exporter.Handler()), log)
	cancel()
	loop.Wait()
	return err
}

// runMatcher is the inventory, the matching and the metrics — the service ADR 0001 describes.
// Whether it catalogues in this process or hands the work to a pool is the one thing that
// differs between a single-pod installation and a distributed one.
func runMatcher(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	// Either listener dying takes the process down. A matcher whose work API never came up
	// would otherwise keep filling a queue no worker can reach, and report every digest as
	// pending for as long as it ran.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	exporter := metrics.New()

	pods, err := kube.Pods(cfg.Kubeconfig, "kiebitzr/"+version.Version)
	if err != nil {
		return fmt.Errorf("kubernetes access: %w", err)
	}

	store, err := cache.New(cfg.CacheDir)
	if err != nil {
		return fmt.Errorf("cache: %w", err)
	}

	// Validated before anything is served, so a wrong severity or a broken ignore file is a
	// start-up error and not a surprise in the first run.
	database, err := vulndb.New(vulndb.Config{
		Dir:         store.DatabaseDir(),
		MinSeverity: cfg.MinSeverity,
		OnlyFixed:   cfg.OnlyFixed,
		IgnoreFile:  cfg.IgnoreFile,
	}, version.Version)
	if err != nil {
		return fmt.Errorf("vulnerability database: %w", err)
	}

	// Loaded here for the same reason as the ignore file: a rule that does not do what it says
	// is invisible in the metrics — nothing else can check a classification — so it has to be
	// a start-up error rather than a surprise on the dashboard weeks later (ADR 0013).
	access, err := buildaccess.Load(cfg.BuildAccessFile)
	if err != nil {
		return fmt.Errorf("build access rules: %w", err)
	}

	catalogue, work, err := cataloguing(cfg, store, exporter, log)
	if err != nil {
		return err
	}

	run := runner.New(pods, store, catalogue, database, exporter, log, runner.Options{
		Interval:          cfg.Interval,
		Timeout:           cfg.RunTimeout,
		CatalogueTimeout:  cfg.CatalogueTimeout,
		ExcludeNamespaces: cfg.ExcludeNamespaces,
		UpgradeScope:      cfg.UpgradeScope,
		BuildAccess:       access,
	})
	// Zero candidates is the default and switches the check off, so the two upgrade metrics
	// have no series at all rather than zeroes that would read like answers (ADR 0011).
	if cfg.UpgradeCandidates > 0 {
		selector, err := upgrade.NewSelector(cfg.Platform, cfg.UpgradeCandidates)
		if err != nil {
			return fmt.Errorf("candidate selector: %w", err)
		}
		run = run.WithCandidates(selector)
		log.Info("checking whether fixes are deployable",
			"candidates", cfg.UpgradeCandidates, "scope", cfg.UpgradeScope)
	}

	var loop sync.WaitGroup
	loop.Go(func() { run.Loop(ctx) })

	// Buffered for both listeners, so neither goroutine can block on a send that nobody is
	// reading yet.
	errc := make(chan error, 2)
	if work != nil {
		loop.Go(func() {
			defer cancel()
			errc <- serve(ctx, cfg.WorkListen, work, log)
		})
	}
	loop.Go(func() {
		defer cancel()
		errc <- serve(ctx, cfg.Listen, newMux(exporter.Handler()), log)
	})

	loop.Wait()
	close(errc)

	var errs []error
	for err := range errc {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// cataloguing builds the stage that turns digests into SBOMs, and the work API if the stage is
// a pool. It returns a nil handler when there is nothing to serve.
func cataloguing(
	cfg config.Config, store *cache.Store, exporter *metrics.Exporter, log *slog.Logger,
) (runner.Cataloguing, http.Handler, error) {
	cataloguer, err := catalog.New(cfg.Platform)
	if err != nil {
		return nil, nil, fmt.Errorf("cataloguer: %w", err)
	}

	if cfg.CatalogueLocally {
		return runner.NewSerial(cataloguer, store, log), nil, nil
	}

	queue := workq.New(workq.Options{
		Deadline:    cfg.WorkDeadline,
		MaxAttempts: cfg.WorkAttempts,
	})
	pool := dispatch.NewPool(queue)
	// Registered before anything is served, which is the contract of QueueDepth.
	if err := exporter.QueueDepth(pool.Depth); err != nil {
		return nil, nil, err
	}
	return pool, dispatch.NewServer(queue, store, log, dispatch.DefaultPollTimeout).Handler(), nil
}

// serve runs one HTTP server until ctx is cancelled, then drains it.
//
// Both roles need this, and the matcher needs it twice: the scrape endpoint and the work API
// are separate listeners on purpose, so a POST surface is not mounted next to /metrics and the
// two can be told apart by a network policy.
func serve(ctx context.Context, addr string, handler http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Bound here rather than inside ListenAndServe, so that a port which cannot be bound is an
	// error before anything claims to be listening. With the bind inside the goroutine, the
	// log line below was printed next to a server that had not bound yet and reported an
	// address it never got — which reads as success and sends an operator looking in the wrong
	// place. The listener's own address is logged for the same reason: `:8080` resolves to
	// what was actually taken.
	// ctx bounds the bind itself, not the listener's life: a shutdown while the address is
	// still being acquired ends it here instead of after the fact.
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Info("listening", "addr", listener.Addr().String())

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(listener) }()

	select {
	case err := <-errc:
		return fmt.Errorf("serve %s: %w", addr, err)
	case <-ctx.Done():
	}

	// Deliberately not derived from ctx: ctx is already cancelled at this point, and a
	// shutdown context inherited from it would expire before a single connection drained.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	//nolint:contextcheck // not inheriting ctx is the point: it is already cancelled here, so
	// a derived context would expire before a single connection could drain.
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("shutdown %s: %w", addr, err)
	}
	return nil
}

func newMux(metricsHandler http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /metrics", metricsHandler)
	return mux
}
