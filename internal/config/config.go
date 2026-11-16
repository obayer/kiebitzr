// Package config holds the runtime configuration of the service. Every value a deployment may
// need to change is a flag, and every flag can also be given as an environment variable so a
// deployment can configure the service from a ConfigMap; nothing about an installation is
// compiled in. The command line wins over the environment (ADR 0007).
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// envPrefix prefixes every environment variable that configures this service.
//
// envTestPrefix is carved out of it: the integration tests read KIEBITZR_TEST_IMAGE and
// KIEBITZR_TEST_PLATFORM (internal/catalog, internal/runner), and neither is a flag. Without
// the exception, running those tests would report both as unknown.
const (
	envPrefix     = "KIEBITZR_"
	envTestPrefix = envPrefix + "TEST_"
)

// envName is the environment variable a flag can also be given as: -min-severity becomes
// KIEBITZR_MIN_SEVERITY. Deriving it from the flag name rather than keeping a table is what
// stops the two from drifting — a new flag gets its variable without a second edit.
func envName(flagName string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// Defaults. The platform default follows ADR 0001: the architecture to resolve a multi-arch
// index to is configuration, never derived from the nodes (that would need `get nodes`).
const (
	DefaultListen   = ":8080"
	DefaultPlatform = "linux/arm64"
	DefaultCacheDir = "/var/cache/kiebitzr"
	// DefaultInterval follows the vulnerability database, which is published once a day.
	// Scanning more often re-reads every SBOM and re-runs every match to arrive at the same
	// findings, which on a small node is the bulk of its work for nothing.
	DefaultInterval = 24 * time.Hour
	// DefaultRunTimeout is generous on purpose: the first run of a large cluster catalogues
	// every image it finds, and a run cut short while matching publishes nothing.
	DefaultRunTimeout = 2 * time.Hour
	// catalogueShare is the share of the run budget cataloguing may use when
	// -catalogue-timeout is not given. The remainder is what matching and publishing get, and
	// it has to be a remainder: a cold start that spends the whole budget cataloguing would
	// publish nothing at all, which is the failure the pending accounting exists to avoid.
	// Three quarters of the two-hour default leaves half an hour to match, enough for several
	// hundred digests at the measured one to four seconds each.
	catalogueShare = 3.0 / 4.0
)

// Roles a process can run as. One binary and one image cover both, so a cluster with five
// images and one with five hundred run the same artefact (ADR 0009).
const (
	// RoleMatcher takes the inventory, matches SBOMs against the vulnerability database and
	// serves the metrics. There is one of these.
	RoleMatcher = "matcher"
	// RoleWorker catalogues images it is handed. It holds no cache, no database and no
	// Kubernetes credential; there can be as many as the work needs.
	RoleWorker = "worker"
)

// Defaults for the work the matcher hands out.
const (
	// DefaultWorkDeadline has to exceed the time cataloguing one image takes, or healthy work
	// is handed out twice. The measured figure is tens of seconds per image.
	DefaultWorkDeadline = 10 * time.Minute
	// DefaultWorkAttempts bounds how often an item is offered again when no answer comes back
	// at all. It does not bound reported failures: a worker that answers has answered.
	DefaultWorkAttempts = 3
)

// platformPattern matches `os/arch` and `os/arch/variant`, e.g. linux/arm64 or linux/arm/v7.
var platformPattern = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$`)

// Config is the fully validated configuration of one process.
type Config struct {
	// Role is what this process does: RoleMatcher or RoleWorker.
	Role string
	// CatalogueLocally is whether the matcher catalogues images in its own process. True is
	// the single-pod installation ADR 0001 describes; a deployment with workers sets it false.
	// It is explicit rather than inferred from whether a worker has polled recently, because
	// the two behave very differently and an operator has to be able to tell which is running.
	CatalogueLocally bool
	// WorkListen is the address serving the work API, separate from Listen. Empty serves no
	// work API at all.
	WorkListen string
	// MatcherURL is where a worker asks for work.
	MatcherURL string
	// WorkDeadline is how long a handed-out digest may stay out before it is offered again.
	WorkDeadline time.Duration
	// WorkAttempts bounds how often a digest is handed out when no answer comes back.
	WorkAttempts int
	// Listen is the address serving /healthz and /metrics.
	Listen string
	// Platform selects the manifest a multi-arch index is resolved to before cataloguing.
	Platform string
	// CacheDir holds the digest-addressed SBOMs and the vulnerability database.
	CacheDir string
	// Interval is the time between the start of two runs.
	Interval time.Duration
	// RunTimeout bounds a single run. It is deliberately not tied to Interval: a cold start
	// catalogues every running image and can easily take longer than one interval, and a run
	// that is cut short while matching publishes nothing at all.
	RunTimeout time.Duration
	// CatalogueTimeout bounds the cataloguing stage within a run. Zero means "derive it from
	// RunTimeout", which validate() does, so the two can never contradict each other.
	CatalogueTimeout time.Duration
	// Kubeconfig is a path to a kubeconfig file; empty means in-cluster configuration. Only
	// a build with the `dev` tag has a flag for it and can act on it.
	Kubeconfig string
	// ExcludeNamespaces are namespaces whose pods are ignored completely: not inventoried,
	// not catalogued, not reported. Everything running there becomes invisible to the
	// metrics, which is the point and the risk.
	ExcludeNamespaces []string
	// MinSeverity drops findings below this severity; empty reports every finding. The name
	// is validated where it is used, against the severities the matcher knows.
	MinSeverity string
	// OnlyFixed reports only findings that have a fix available.
	OnlyFixed bool
	// IgnoreFile is a YAML file of ignore rules; empty means none.
	IgnoreFile string
	// BuildAccessFile is a YAML file classifying repositories by whether anybody here can get
	// a build of the images in them; empty leaves every image `unknown`. Unknown is a work
	// item and not a verdict, which is why no file is not the same as declaring everything
	// unreachable (ADR 0013).
	BuildAccessFile string
	// UpgradeCandidates is how many candidate images per repository are checked, to find out
	// whether a deployable image exists that clears a finding. Zero disables the check, and
	// zero is the default: it costs a tag listing per repository and one SBOM per candidate —
	// measured at 19 to 34 minutes for the default scope on a Cortex-A72 (ADR 0011).
	//
	// One value carries both the switch and the choice, as with WorkListen, IgnoreFile and
	// MinSeverity. More than one candidate is worth the cost because the newest build is not
	// reliably the newest content: a backport built recently is only included if the next few
	// are looked at too, and a nightly then consumes a slot instead of distorting the answer.
	UpgradeCandidates int
	// UpgradeScope is which findings get a candidate check: ScopeExploited or ScopeFixable.
	// It exists because this is the cost lever — the wide mode roughly triples the work — so
	// it is chosen rather than inherited.
	UpgradeScope string
}

// Scopes for -upgrade-scope.
const (
	// ScopeExploited checks only findings that are known-exploited and carry a fixed version.
	// The default, because those are the only findings that could ever page: an alarm has to
	// be clearable by whoever it wakes.
	ScopeExploited = "exploited"
	// ScopeFixable checks every High and Critical finding with a fixed version. More
	// complete, and on the pilot cluster roughly three times the cataloguing for findings
	// nobody acts on tonight.
	ScopeFixable = "fixable"
)

// ErrHelp is returned when the caller asked for the flag usage; the process should exit
// successfully without doing any work.
var ErrHelp = flag.ErrHelp

// Parse builds a Config from command-line arguments and the environment. args excludes the
// program name. Usage and error output go to out, so a test can read them.
func Parse(args []string, out io.Writer) (Config, error) {
	var cfg Config
	var excludeNamespaces string

	fs := newFlagSet(out, &cfg, &excludeNamespaces)

	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("parse flags: %w", err)
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	// After Parse, so the flag set knows which flags were given explicitly, and before
	// excludeNamespaces is read, because the environment may be what fills it.
	if err := applyEnv(fs); err != nil {
		return Config{}, err
	}

	namespaces, err := namespaceList(excludeNamespaces)
	if err != nil {
		return Config{}, err
	}
	cfg.ExcludeNamespaces = namespaces

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	cfg.resolve()
	return cfg, nil
}

// applyEnv fills flags that were not given on the command line from the environment.
//
// The command line wins: a value passed explicitly is never overridden by a ConfigMap, which
// is what keeps an ad-hoc debugging run predictable. Each value goes through the flag's own
// parser, so KIEBITZR_INTERVAL is validated exactly like -interval and a malformed value is a
// start-up error rather than a silently kept default.
func applyEnv(fs *flag.FlagSet) error {
	given := make(map[string]struct{})
	fs.Visit(func(f *flag.Flag) { given[f.Name] = struct{}{} })

	var errs []error
	fs.VisitAll(func(f *flag.Flag) {
		if _, ok := given[f.Name]; ok {
			return
		}
		key := envName(f.Name)
		value, ok := os.LookupEnv(key)
		if !ok {
			return
		}
		if err := f.Value.Set(value); err != nil {
			errs = append(errs, fmt.Errorf("%s=%q: %w", key, value, err))
		}
	})
	return errors.Join(errs...)
}

// UnknownEnvVars returns the names of KIEBITZR_* variables in the environment that no flag of
// this build corresponds to, sorted.
//
// It exists because `envFrom` puts every key of a ConfigMap into the environment, and a
// misspelled key would otherwise be ignored in silence — leaving an operator to wonder why a
// value they set changes nothing. Note that a release build legitimately reports
// KIEBITZR_KUBECONFIG here: the flag is not registered without the `dev` tag (ADR 0004), so
// the variable has no effect, which is exactly what the caller should say out loud.
func UnknownEnvVars() []string {
	var (
		cfg               Config
		excludeNamespaces string
	)
	known := make(map[string]struct{})
	newFlagSet(io.Discard, &cfg, &excludeNamespaces).VisitAll(func(f *flag.Flag) {
		known[envName(f.Name)] = struct{}{}
	})

	var unknown []string
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(name, envPrefix) || strings.HasPrefix(name, envTestPrefix) {
			continue
		}
		if _, ok := known[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	slices.Sort(unknown)
	return unknown
}

// newFlagSet registers every flag against the given targets. Parse and UnknownEnvVars share
// it so that the set of flags, and with it the set of environment variables, is defined once.
func newFlagSet(out io.Writer, cfg *Config, excludeNamespaces *string) *flag.FlagSet {
	fs := flag.NewFlagSet("kiebitzr", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&cfg.Role, "role", RoleMatcher, "what this process does: matcher (inventory, matching, metrics) or worker (cataloguing only)")
	fs.BoolVar(&cfg.CatalogueLocally, "catalogue-locally", true, "whether the matcher catalogues images itself; set false when workers do it")
	fs.StringVar(&cfg.WorkListen, "work-listen", "", "address serving the work API workers poll, separate from -listen; empty serves none")
	fs.StringVar(&cfg.MatcherURL, "matcher-url", "", "where a worker asks for work, e.g. http://kiebitzr:8081")
	fs.DurationVar(&cfg.WorkDeadline, "work-deadline", DefaultWorkDeadline, "how long a handed-out digest may stay out before it is offered again")
	fs.IntVar(&cfg.WorkAttempts, "work-attempts", DefaultWorkAttempts, "how often a digest is handed out when no answer comes back at all")
	fs.StringVar(&cfg.Listen, "listen", DefaultListen, "address serving /healthz and /metrics")
	fs.StringVar(&cfg.Platform, "platform", DefaultPlatform, "platform a multi-arch image index is resolved to, as os/arch[/variant]")
	fs.StringVar(&cfg.CacheDir, "cache-dir", DefaultCacheDir, "directory for cached SBOMs and the vulnerability database")
	fs.DurationVar(&cfg.Interval, "interval", DefaultInterval, "time between the start of two runs")
	fs.DurationVar(&cfg.RunTimeout, "run-timeout", DefaultRunTimeout, "how long a single run may take before it is given up")
	fs.DurationVar(&cfg.CatalogueTimeout, "catalogue-timeout", 0, "how long cataloguing may take within a run; digests not reached are reported as pending. Zero derives it from -run-timeout, leaving time to match and publish")
	if kubeconfigSupported {
		fs.StringVar(&cfg.Kubeconfig, "kubeconfig", "", "path to a kubeconfig file; empty uses the in-cluster configuration")
	}
	fs.StringVar(excludeNamespaces, "exclude-namespaces", "", "comma-separated namespaces to ignore completely; their images are neither scanned nor reported")
	fs.StringVar(&cfg.MinSeverity, "min-severity", "", "drop findings below this severity (negligible, low, medium, high, critical); empty reports all")
	fs.BoolVar(&cfg.OnlyFixed, "only-fixed", false, "report only findings that have a fix available")
	// No backquotes in a usage string: the flag package reads the first backquoted word as
	// the argument's name, which turned this into "-ignore-file ignore:".
	fs.StringVar(&cfg.IgnoreFile, "ignore-file", "", "path to a YAML file of ignore rules, listed under an ignore: key; empty means none")
	fs.StringVar(&cfg.BuildAccessFile, "build-access-file", "", "path to a YAML file classifying repositories by whether anybody here can get a build of them, listed under a build-access: key; empty leaves every image unknown")
	fs.IntVar(&cfg.UpgradeCandidates, "upgrade-candidates", 0, "how many candidate images per repository to check, to find out whether a deployable image exists that clears a finding; zero disables it. Costs a tag listing per repository and one SBOM per candidate — see the running runbook")
	fs.StringVar(&cfg.UpgradeScope, "upgrade-scope", ScopeExploited, "which findings get a candidate check: exploited (known-exploited with a fix, the only ones that can page) or fixable (every High and Critical with a fix, roughly three times the work)")

	return fs
}

// namespaceList splits and checks a comma-separated list of namespaces. Names are validated
// against the rule Kubernetes itself applies, so a typo is a start-up error rather than an
// exclusion that silently matches nothing.
func namespaceList(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	var (
		names []string
		errs  []error
	)
	seen := make(map[string]struct{})
	for name := range strings.SplitSeq(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			errs = append(errs, errors.New("exclude-namespaces contains an empty name"))
			continue
		}
		if problems := validation.IsDNS1123Label(name); len(problems) > 0 {
			errs = append(errs, fmt.Errorf("namespace %q: %s", name, strings.Join(problems, "; ")))
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return names, nil
}

func (c *Config) validate() error {
	var errs []error

	errs = append(errs, c.validateRole()...)

	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		errs = append(errs, fmt.Errorf("listen %q is not a host:port address: %w", c.Listen, err))
	}
	if c.WorkListen != "" {
		if _, _, err := net.SplitHostPort(c.WorkListen); err != nil {
			errs = append(errs, fmt.Errorf("work-listen %q is not a host:port address: %w", c.WorkListen, err))
		}
	}
	if c.WorkDeadline <= 0 {
		errs = append(errs, fmt.Errorf("work-deadline %s must be positive", c.WorkDeadline))
	}
	if c.WorkAttempts <= 0 {
		errs = append(errs, fmt.Errorf("work-attempts %d must be positive", c.WorkAttempts))
	}
	if !platformPattern.MatchString(c.Platform) {
		errs = append(errs, fmt.Errorf("platform %q is not of the form os/arch[/variant]", c.Platform))
	}
	if c.CacheDir == "" {
		errs = append(errs, errors.New("cache-dir must not be empty"))
	}
	if c.Interval <= 0 {
		errs = append(errs, fmt.Errorf("interval %s must be positive", c.Interval))
	}
	if c.RunTimeout <= 0 {
		errs = append(errs, fmt.Errorf("run-timeout %s must be positive", c.RunTimeout))
	}
	if c.CatalogueTimeout < 0 {
		errs = append(errs, fmt.Errorf("catalogue-timeout %s must not be negative", c.CatalogueTimeout))
	}
	if c.CatalogueTimeout >= c.RunTimeout && c.RunTimeout > 0 {
		errs = append(errs, fmt.Errorf(
			"catalogue-timeout %s must be shorter than run-timeout %s, or matching never gets to publish",
			c.CatalogueTimeout, c.RunTimeout))
	}
	if c.UpgradeCandidates < 0 {
		errs = append(errs, fmt.Errorf(
			"upgrade-candidates %d must not be negative", c.UpgradeCandidates))
	}
	if c.UpgradeScope != ScopeExploited && c.UpgradeScope != ScopeFixable {
		errs = append(errs, fmt.Errorf(
			"upgrade-scope %q must be %q or %q", c.UpgradeScope, ScopeExploited, ScopeFixable))
	}
	return errors.Join(errs...)
}

// validateRole rejects the combinations that would start a process doing nothing useful.
// Each of these is silent at runtime if it is allowed through: a worker with no matcher polls
// nowhere, and a matcher that neither catalogues nor serves work fills a queue nobody drains.
func (c *Config) validateRole() []error {
	var errs []error
	switch c.Role {
	case RoleWorker:
		if c.MatcherURL == "" {
			errs = append(errs, errors.New("role worker needs -matcher-url: a worker asks for its work"))
		}
		if c.WorkListen != "" {
			errs = append(errs, errors.New("role worker cannot serve -work-listen: workers take work, they do not hand it out"))
		}
	case RoleMatcher:
		if c.WorkListen != "" && c.CatalogueLocally {
			errs = append(errs, errors.New(
				"-work-listen needs -catalogue-locally=false: a matcher that catalogues itself never fills the queue, and workers would poll an empty one forever"))
		}
		if c.WorkListen == "" && !c.CatalogueLocally {
			errs = append(errs, errors.New(
				"-catalogue-locally=false needs -work-listen: nothing would catalogue anything"))
		}
		if c.MatcherURL != "" {
			errs = append(errs, errors.New("-matcher-url belongs to a worker; a matcher is the one being asked"))
		}
	default:
		errs = append(errs, fmt.Errorf("role %q must be %q or %q", c.Role, RoleMatcher, RoleWorker))
	}
	return errs
}

// resolve fills in the values that are derived from others rather than defaulted to a
// constant. It runs after validation, so it never has to cope with a nonsensical input.
func (c *Config) resolve() {
	if c.CatalogueTimeout == 0 {
		c.CatalogueTimeout = time.Duration(float64(c.RunTimeout) * catalogueShare)
	}
}

// LogAttrs is every setting with the value that is actually in effect, for the one log line
// that answers "did my ConfigMap land".
//
// It reads the **resolved** configuration rather than the flag set, which matters for the
// values that are derived from others: `-catalogue-timeout` is zero as a flag and three
// quarters of `-run-timeout` in effect, and an operator comparing a pod against a ConfigMap
// needs the second number. Every role logs every setting, including the ones it ignores — a
// value that arrived but does nothing is exactly the kind of mistake this line exists to
// show, and which role reads what is in the running runbook.
//
// TestLogAttrsCoversEveryFlag keeps this list complete: a new flag without a line here fails
// the test rather than going quietly missing from the one place somebody looks.
func (c *Config) LogAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("role", c.Role),
		slog.String("listen", c.Listen),
		slog.String("platform", c.Platform),
		slog.String("cache_dir", c.CacheDir),
		slog.String("interval", c.Interval.String()),
		slog.String("run_timeout", c.RunTimeout.String()),
		slog.String("catalogue_timeout", c.CatalogueTimeout.String()),
		slog.Bool("catalogue_locally", c.CatalogueLocally),
		slog.String("work_listen", c.WorkListen),
		slog.String("matcher_url", redactUserinfo(c.MatcherURL)),
		slog.String("work_deadline", c.WorkDeadline.String()),
		slog.Int("work_attempts", c.WorkAttempts),
		slog.String("exclude_namespaces", strings.Join(c.ExcludeNamespaces, ",")),
		slog.String("min_severity", c.MinSeverity),
		slog.Bool("only_fixed", c.OnlyFixed),
		slog.String("ignore_file", c.IgnoreFile),
		slog.String("build_access_file", c.BuildAccessFile),
		slog.Int("upgrade_candidates", c.UpgradeCandidates),
		slog.String("upgrade_scope", c.UpgradeScope),
		slog.String("kubeconfig", c.Kubeconfig),
	}
}

// redactUserinfo removes a username and password embedded in a URL before it is logged.
//
// Nothing here supports credentials in `-matcher-url` — the work API is internal and
// unauthenticated — but somebody will eventually put them there, and a log line is the last
// place a credential should turn up. A URL that cannot be parsed is reported as unparseable
// rather than printed, for the same reason.
func redactUserinfo(raw string) string {
	if raw == "" || !strings.Contains(raw, "@") {
		return raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "<unparseable>"
	}
	if parsed.User == nil {
		return raw
	}
	parsed.User = url.User("redacted")
	return parsed.String()
}
