package config

import (
	"errors"
	"flag"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse(nil, io.Discard)
	if err != nil {
		t.Fatalf("Parse(nil) = %v, want no error", err)
	}
	want := Config{
		Role:             RoleMatcher,
		CatalogueLocally: true,
		WorkDeadline:     DefaultWorkDeadline,
		WorkAttempts:     DefaultWorkAttempts,

		Listen:     DefaultListen,
		Platform:   DefaultPlatform,
		CacheDir:   DefaultCacheDir,
		Interval:   DefaultInterval,
		RunTimeout: DefaultRunTimeout,
		// Not a constant of its own: derived from the run timeout, so the two cannot
		// contradict each other.
		CatalogueTimeout: 90 * time.Minute,
		// The candidate check is off by default (zero), but its scope still has one, so that
		// turning the check on does not also require choosing the expensive mode.
		UpgradeScope: ScopeExploited,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("Parse(nil) = %+v, want %+v", cfg, want)
	}
}

func TestParse(t *testing.T) {
	args := []string{
		"-listen", "127.0.0.1:9090",
		"-platform", "linux/arm/v7",
		"-cache-dir", "/var/tmp/kiebitzr",
		"-interval", "15m",
		"-run-timeout", "45m",
		"-catalogue-timeout", "30m",
		"-exclude-namespaces", "kube-system, monitoring",
		"-min-severity", "high",
		"-only-fixed",
		"-ignore-file", "/etc/kiebitzr/ignore.yaml",
		"-upgrade-candidates", "3",
		"-upgrade-scope", "fixable",
	}
	cfg, err := Parse(args, io.Discard)
	if err != nil {
		t.Fatalf("Parse(%v) = %v, want no error", args, err)
	}
	want := Config{
		Role:             RoleMatcher,
		CatalogueLocally: true,
		WorkDeadline:     DefaultWorkDeadline,
		WorkAttempts:     DefaultWorkAttempts,

		Listen:            "127.0.0.1:9090",
		Platform:          "linux/arm/v7",
		CacheDir:          "/var/tmp/kiebitzr",
		Interval:          15 * time.Minute,
		RunTimeout:        45 * time.Minute,
		CatalogueTimeout:  30 * time.Minute,
		ExcludeNamespaces: []string{"kube-system", "monitoring"},
		MinSeverity:       "high",
		OnlyFixed:         true,
		IgnoreFile:        "/etc/kiebitzr/ignore.yaml",
		UpgradeCandidates: 3,
		UpgradeScope:      ScopeFixable,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("Parse(%v) = %+v, want %+v", args, cfg, want)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"listen without port", []string{"-listen", "localhost"}},
		{"platform without arch", []string{"-platform", "linux"}},
		{"platform with too many parts", []string{"-platform", "linux/arm64/v8/extra"}},
		{"empty cache dir", []string{"-cache-dir", ""}},
		{"zero interval", []string{"-interval", "0"}},
		{"zero run timeout", []string{"-run-timeout", "0"}},
		{"negative run timeout", []string{"-run-timeout", "-1h"}},
		{"negative interval", []string{"-interval", "-5m"}},
		{"negative catalogue timeout", []string{"-catalogue-timeout", "-5m"}},
		// Cataloguing may not use the whole run: matching and publishing need what is left,
		// and a run that spends everything on cataloguing publishes nothing at all.
		{"catalogue timeout equal to the run timeout", []string{"-run-timeout", "1h", "-catalogue-timeout", "1h"}},
		{"catalogue timeout beyond the run timeout", []string{"-run-timeout", "1h", "-catalogue-timeout", "2h"}},
		{"unknown flag", []string{"-nope"}},
		{"positional argument", []string{"scan"}},
		{"negative upgrade candidates", []string{"-upgrade-candidates", "-1"}},
		{"unknown upgrade scope", []string{"-upgrade-scope", "everything"}},
		{"empty upgrade scope", []string{"-upgrade-scope", ""}},
		// Role combinations that would start a process doing nothing useful. Each of these is
		// silent at runtime if it is allowed through, which is why they are start-up errors.
		{"unknown role", []string{"-role", "cataloguer"}},
		{"worker without a matcher", []string{"-role", "worker"}},
		{"worker serving work", []string{
			"-role", "worker", "-matcher-url", "http://kiebitzr:8081", "-work-listen", ":8081",
		}},
		{"matcher serving work while cataloguing itself", []string{"-work-listen", ":8081"}},
		{"matcher that neither catalogues nor hands out work", []string{"-catalogue-locally=false"}},
		{"matcher pointed at a matcher", []string{"-matcher-url", "http://kiebitzr:8081"}},
		{"work-listen without a port", []string{
			"-work-listen", "localhost", "-catalogue-locally=false",
		}},
		{"zero work deadline", []string{"-work-deadline", "0"}},
		{"zero work attempts", []string{"-work-attempts", "0"}},
		// Zero is valid and means "update every run", so only the sign is rejected here. The
		// upper bound belongs to Grype and is checked in internal/vulndb.
		{"negative db max age", []string{"-db-max-age", "-1h"}},
		{"unparseable db max age", []string{"-db-max-age", "three days"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.args, io.Discard); err == nil {
				t.Fatalf("Parse(%v) = no error, want one", tt.args)
			}
		})
	}
}

// Zero has to stay a legal value, because it is how the flag is switched off and it is the
// default: the opt-in only exists if "update on every run" is expressible.
func TestParseAcceptsDBMaxAge(t *testing.T) {
	cfg, err := Parse([]string{"-db-max-age", "72h"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse(-db-max-age=72h) = %v, want no error", err)
	}
	if cfg.DBMaxAge != 72*time.Hour {
		t.Fatalf("DBMaxAge = %s, want 72h", cfg.DBMaxAge)
	}

	off, err := Parse([]string{"-db-max-age", "0"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse(-db-max-age=0) = %v, want no error", err)
	}
	if off.DBMaxAge != 0 {
		t.Fatalf("DBMaxAge = %s, want zero to switch the skipping off", off.DBMaxAge)
	}
}

// The two shapes a deployment actually uses have to parse.
func TestParseAcceptsBothRoles(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Config
	}{
		{
			name: "matcher handing work to a pool",
			args: []string{"-catalogue-locally=false", "-work-listen", ":8081"},
			want: Config{Role: RoleMatcher, CatalogueLocally: false, WorkListen: ":8081"},
		},
		{
			name: "worker",
			args: []string{"-role", "worker", "-matcher-url", "http://kiebitzr:8081"},
			want: Config{Role: RoleWorker, CatalogueLocally: true, MatcherURL: "http://kiebitzr:8081"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse(tt.args, io.Discard)
			if err != nil {
				t.Fatalf("Parse(%v) = %v, want no error", tt.args, err)
			}
			if cfg.Role != tt.want.Role {
				t.Fatalf("Role = %q, want %q", cfg.Role, tt.want.Role)
			}
			if cfg.CatalogueLocally != tt.want.CatalogueLocally {
				t.Fatalf("CatalogueLocally = %v, want %v", cfg.CatalogueLocally, tt.want.CatalogueLocally)
			}
			if cfg.WorkListen != tt.want.WorkListen || cfg.MatcherURL != tt.want.MatcherURL {
				t.Fatalf("WorkListen/MatcherURL = %q/%q, want %q/%q",
					cfg.WorkListen, cfg.MatcherURL, tt.want.WorkListen, tt.want.MatcherURL)
			}
		})
	}
}

func TestParseExcludeNamespaces(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"none", "", nil},
		{"one", "kube-system", []string{"kube-system"}},
		{"several", "kube-system,monitoring", []string{"kube-system", "monitoring"}},
		{"surrounding spaces are tolerated", " kube-system , monitoring ", []string{"kube-system", "monitoring"}},
		{"order is kept", "monitoring,kube-system", []string{"monitoring", "kube-system"}},
		{"duplicates collapse", "kube-system,kube-system", []string{"kube-system"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]string{"-exclude-namespaces", tt.raw}, io.Discard)
			if err != nil {
				t.Fatalf("Parse(-exclude-namespaces=%q) = %v, want no error", tt.raw, err)
			}
			if !reflect.DeepEqual(cfg.ExcludeNamespaces, tt.want) {
				t.Fatalf("ExcludeNamespaces = %#v, want %#v", cfg.ExcludeNamespaces, tt.want)
			}
		})
	}
}

// A namespace that cannot exist would exclude nothing, and silently. The name is therefore
// checked against the same rule Kubernetes applies.
func TestParseRejectsImpossibleNamespaces(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty entry", "kube-system,,monitoring"},
		{"trailing comma", "kube-system,"},
		{"upper case", "Kube-System"},
		{"underscore", "kube_system"},
		{"leading dash", "-kube-system"},
		{"path", "kube-system/pods"},
		{"too long", strings.Repeat("a", 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]string{"-exclude-namespaces", tt.raw}, io.Discard); err == nil {
				t.Fatalf("Parse(-exclude-namespaces=%q) = no error, want one", tt.raw)
			}
		})
	}
}

// The kubeconfig flag is a development affordance. A production build must not have it at
// all: a flag that exists and does nothing is worse than one that is rejected. This test runs
// in both build configurations and asserts whichever is in force.
func TestKubeconfigFlagOnlyExistsInDevBuilds(t *testing.T) {
	cfg, err := Parse([]string{"-kubeconfig", "/home/user/.kube/config"}, io.Discard)

	if kubeconfigSupported {
		if err != nil {
			t.Fatalf("Parse(-kubeconfig) = %v, want it accepted in a dev build", err)
		}
		if cfg.Kubeconfig != "/home/user/.kube/config" {
			t.Fatalf("Kubeconfig = %q, want the path that was passed", cfg.Kubeconfig)
		}
		return
	}
	if err == nil {
		t.Fatal("Parse(-kubeconfig) = no error, want a production build to reject the flag")
	}
}

// Help must stay recognisable through the wrapping, so main can exit 0 for -h.
func TestParseHelpIsErrHelp(t *testing.T) {
	_, err := Parse([]string{"-h"}, io.Discard)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("Parse(-h) = %v, want flag.ErrHelp", err)
	}
	if !errors.Is(err, ErrHelp) {
		t.Fatalf("Parse(-h) = %v, want config.ErrHelp", err)
	}
}

func TestParseFromEnvironment(t *testing.T) {
	t.Setenv("KIEBITZR_LISTEN", "127.0.0.1:9191")
	t.Setenv("KIEBITZR_INTERVAL", "30m")
	t.Setenv("KIEBITZR_MIN_SEVERITY", "critical")
	t.Setenv("KIEBITZR_ONLY_FIXED", "true")
	t.Setenv("KIEBITZR_EXCLUDE_NAMESPACES", "kube-system, monitoring")

	cfg, err := Parse(nil, io.Discard)
	if err != nil {
		t.Fatalf("Parse(nil) with environment = %v, want no error", err)
	}
	want := Config{
		Role:             RoleMatcher,
		CatalogueLocally: true,
		WorkDeadline:     DefaultWorkDeadline,
		WorkAttempts:     DefaultWorkAttempts,

		Listen:            "127.0.0.1:9191",
		Platform:          DefaultPlatform,
		CacheDir:          DefaultCacheDir,
		Interval:          30 * time.Minute,
		RunTimeout:        DefaultRunTimeout,
		CatalogueTimeout:  90 * time.Minute,
		ExcludeNamespaces: []string{"kube-system", "monitoring"},
		MinSeverity:       "critical",
		OnlyFixed:         true,
		UpgradeScope:      ScopeExploited,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("Parse(nil) with environment = %+v, want %+v", cfg, want)
	}
}

// Precedence is the whole point of the ordering in Parse: a ConfigMap must not override an
// argument someone passed deliberately, or an ad-hoc run cannot be reasoned about.
func TestFlagBeatsEnvironment(t *testing.T) {
	t.Setenv("KIEBITZR_INTERVAL", "30m")

	cfg, err := Parse([]string{"-interval", "5m"}, io.Discard)
	if err != nil {
		t.Fatalf("Parse(-interval=5m) = %v, want no error", err)
	}
	if cfg.Interval != 5*time.Minute {
		t.Fatalf("Interval = %s, want the 5m from the command line", cfg.Interval)
	}
}

// A malformed environment value must stop the process, not leave the default in place: the
// deployment asked for something, and silently doing something else is the worse outcome.
func TestEnvironmentValueIsValidatedLikeAFlag(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"interval is not a duration", "KIEBITZR_INTERVAL", "10x"},
		{"only-fixed is not a bool", "KIEBITZR_ONLY_FIXED", "perhaps"},
		{"listen has no port", "KIEBITZR_LISTEN", "localhost"},
		{"interval is zero", "KIEBITZR_INTERVAL", "0"},
		{"namespace is not a label", "KIEBITZR_EXCLUDE_NAMESPACES", "Not_A_Namespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.key, tt.value)
			if _, err := Parse(nil, io.Discard); err == nil {
				t.Fatalf("Parse(nil) with %s=%q = no error, want one", tt.key, tt.value)
			}
		})
	}
}

func TestUnknownEnvVars(t *testing.T) {
	t.Setenv("KIEBITZR_INTERVAL", "30m")
	t.Setenv("KIEBITZR_INTERVALL", "30m")
	t.Setenv("KIEBITZR_NOPE", "1")
	// Reserved by the integration tests, and deliberately not reported.
	t.Setenv("KIEBITZR_TEST_IMAGE", "example.com/image:tag")
	// Not ours at all.
	t.Setenv("UNRELATED", "1")

	t.Setenv("KIEBITZR_KUBECONFIG", "/home/user/.kube/config")

	// The kubeconfig flag exists only with the `dev` tag (ADR 0004). Without it the variable
	// has no effect, which is precisely why it has to be named.
	want := []string{"KIEBITZR_INTERVALL", "KIEBITZR_NOPE"}
	if !kubeconfigSupported {
		want = []string{"KIEBITZR_INTERVALL", "KIEBITZR_KUBECONFIG", "KIEBITZR_NOPE"}
	}
	if got := UnknownEnvVars(); !reflect.DeepEqual(got, want) {
		t.Fatalf("UnknownEnvVars() = %v, want %v", got, want)
	}
}

// The start-up log is where an operator checks whether a ConfigMap landed, so a flag missing
// from it is a value nobody can verify without a shell in the pod. LogAttrs is hand-written
// because it reports resolved values rather than flag values; this is what keeps it complete.
func TestLogAttrsCoversEveryFlag(t *testing.T) {
	var cfg Config
	var excludeNamespaces string
	fs := newFlagSet(io.Discard, &cfg, &excludeNamespaces)

	logged := make(map[string]struct{})
	for _, attr := range cfg.LogAttrs() {
		logged[attr.Key] = struct{}{}
	}

	fs.VisitAll(func(f *flag.Flag) {
		key := strings.ReplaceAll(f.Name, "-", "_")
		if _, ok := logged[key]; !ok {
			t.Errorf("flag -%s is not in the start-up log; add %q to Config.LogAttrs", f.Name, key)
		}
	})

	// And the other direction, so a flag that goes away does not leave a line behind that
	// reports a value nothing can set any more.
	flags := make(map[string]struct{})
	fs.VisitAll(func(f *flag.Flag) {
		flags[strings.ReplaceAll(f.Name, "-", "_")] = struct{}{}
	})
	for key := range logged {
		// kubeconfig is logged in both builds and is only a flag in the `dev` one (ADR 0004):
		// an empty value in a release build is the honest answer, and omitting the line would
		// make the log's shape depend on the build.
		if key == "kubeconfig" {
			continue
		}
		if _, ok := flags[key]; !ok {
			t.Errorf("the start-up log reports %q, which is no longer a flag", key)
		}
	}
}

// A credential in -matcher-url would otherwise be printed in full on every start.
func TestLogAttrsRedactsCredentialsInTheMatcherURL(t *testing.T) {
	tests := map[string]string{
		"http://user:secret@kiebitzr:8081": "http://redacted@kiebitzr:8081",
		"http://kiebitzr:8081":             "http://kiebitzr:8081",
		"":                                 "",
		"http://%zz@host":                  "<unparseable>",
	}
	for raw, want := range tests {
		t.Run(raw, func(t *testing.T) {
			cfg := Config{MatcherURL: raw}
			for _, attr := range cfg.LogAttrs() {
				if attr.Key != "matcher_url" {
					continue
				}
				if got := attr.Value.String(); got != want {
					t.Fatalf("matcher_url = %q, want %q", got, want)
				}
				return
			}
			t.Fatal("matcher_url is not logged at all")
		})
	}
}
