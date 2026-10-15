package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

type config struct {
	Listen             string
	Token              string
	TokenFile          string
	Cert               string
	Key                string
	Debug              bool
	MaxRealms          int
	MaxRealmsPerIP     int
	ConnectRatePerIP   int
	TrustedProxyHeader string
	TrustedProxies     string
	RealmNamePattern   string
	MetricsListen      string
}

var (
	realmToken string
	debugLogs  bool
)

func debugf(format string, v ...any) {
	if debugLogs {
		log.Printf("debug: "+format, v...)
	}
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	scfg, err := cfg.serverConfig()
	if err != nil {
		log.Fatal(err)
	}
	realmToken = cfg.Token
	debugLogs = cfg.Debug

	s := newServer(scfg)
	if cfg.MetricsListen != "" {
		s.metrics = newMetrics()
		s.metrics.registerGauges(s)
		go serveMetrics(cfg.MetricsListen, s.metrics.reg)
	}
	// The reaper reads s.metrics, so start it only after metrics are set up.
	go s.reaper()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		// Close idle keep-alive connections. ReadTimeout and WriteTimeout
		// stay unset because they would cut off long-lived /events streams.
		IdleTimeout: 2 * time.Minute,
	}
	log.Printf("hysteria realm server listening on %s", cfg.Listen)
	if debugLogs {
		log.Println("debug logging enabled")
	}
	if cfg.Cert != "" {
		log.Fatal(srv.ListenAndServeTLS(cfg.Cert, cfg.Key))
	}
	log.Println("warning: serving plain HTTP; set HYSTERIA_REALM_CERT and HYSTERIA_REALM_KEY for TLS")
	log.Fatal(srv.ListenAndServe())
}

func parseConfig(args []string) (config, error) {
	var envErrs []error
	envInt := func(k string, def int) int {
		n, err := getenvInt(k, def)
		if err != nil {
			envErrs = append(envErrs, err)
		}
		return n
	}
	envBool := func(k string, def bool) bool {
		b, err := getenvBool(k, def)
		if err != nil {
			envErrs = append(envErrs, err)
		}
		return b
	}
	cfg := config{
		Listen:             getenv("HYSTERIA_REALM_LISTEN", ":8443"),
		Token:              getenv("HYSTERIA_REALM_TOKEN", ""),
		TokenFile:          getenv("HYSTERIA_REALM_TOKEN_FILE", ""),
		Cert:               getenv("HYSTERIA_REALM_CERT", ""),
		Key:                getenv("HYSTERIA_REALM_KEY", ""),
		Debug:              envBool("HYSTERIA_REALM_DEBUG", false),
		MaxRealms:          envInt("HYSTERIA_REALM_MAX_REALMS", 65536),
		MaxRealmsPerIP:     envInt("HYSTERIA_REALM_MAX_REALMS_PER_IP", 4),
		ConnectRatePerIP:   envInt("HYSTERIA_REALM_CONNECT_RATE_PER_IP", 60),
		TrustedProxyHeader: getenv("HYSTERIA_REALM_TRUSTED_PROXY_HEADER", ""),
		TrustedProxies:     getenv("HYSTERIA_REALM_TRUSTED_PROXIES", ""),
		RealmNamePattern:   getenv("HYSTERIA_REALM_NAME_PATTERN", defaultRealmNamePattern),
		MetricsListen:      getenv("HYSTERIA_REALM_METRICS_LISTEN", ""),
	}
	if err := errors.Join(envErrs...); err != nil {
		return config{}, err
	}
	fs := pflag.NewFlagSet("hysteria-realm-server", pflag.ContinueOnError)
	fs.StringVar(&cfg.Listen, "listen", cfg.Listen, "address to listen on")
	fs.StringVar(&cfg.Token, "token", cfg.Token, "shared bearer token for registration and connection")
	fs.StringVar(&cfg.TokenFile, "token-file", cfg.TokenFile, "file to read the shared bearer token from")
	fs.StringVar(&cfg.Cert, "cert", cfg.Cert, "path to TLS certificate")
	fs.StringVar(&cfg.Key, "key", cfg.Key, "path to TLS private key")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "enable debug logs")
	fs.IntVar(&cfg.MaxRealms, "max-realms", cfg.MaxRealms, "maximum total realms (0 = unlimited)")
	fs.IntVar(&cfg.MaxRealmsPerIP, "max-realms-per-ip", cfg.MaxRealmsPerIP, "maximum realms per client IP (0 = unlimited)")
	fs.IntVar(&cfg.ConnectRatePerIP, "connect-rate-per-ip", cfg.ConnectRatePerIP, "maximum connect requests per minute per client IP (0 = unlimited)")
	fs.StringVar(&cfg.TrustedProxyHeader, "trusted-proxy-header", cfg.TrustedProxyHeader, "header to read real client IP from (e.g. X-Forwarded-For)")
	fs.StringVar(&cfg.TrustedProxies, "trusted-proxies", cfg.TrustedProxies, "comma-separated IPs/CIDRs of proxies allowed to set the trusted proxy header")
	fs.StringVar(&cfg.RealmNamePattern, "realm-name-pattern", cfg.RealmNamePattern, "regex realm names must match")
	fs.StringVar(&cfg.MetricsListen, "metrics-listen", cfg.MetricsListen, "address to expose Prometheus metrics on (empty = disabled)")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if err := cfg.loadTokenFile(); err != nil {
		return config{}, err
	}
	if err := cfg.validate(); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func (c *config) loadTokenFile() error {
	if c.TokenFile == "" {
		return nil
	}
	if c.Token != "" {
		return errors.New("set either a token or a token file, not both")
	}
	bs, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return fmt.Errorf("read token file: %w", err)
	}
	c.Token = strings.TrimSpace(string(bs))
	if c.Token == "" {
		return fmt.Errorf("token file %s is empty", c.TokenFile)
	}
	return nil
}

func (c *config) validate() error {
	if c.Token == "" {
		return errors.New("a token is required: set HYSTERIA_REALM_TOKEN or HYSTERIA_REALM_TOKEN_FILE")
	}
	if (c.Cert == "") != (c.Key == "") {
		// Falling back to plain HTTP here would send the token unencrypted
		// because of a typo in one path.
		return errors.New("TLS needs both a certificate and a key: set both HYSTERIA_REALM_CERT and HYSTERIA_REALM_KEY, or neither to serve plain HTTP")
	}
	for _, v := range []struct {
		name  string
		value int
	}{
		{"max realms", c.MaxRealms},
		{"max realms per IP", c.MaxRealmsPerIP},
		{"connect rate per IP", c.ConnectRatePerIP},
	} {
		if v.value < 0 {
			return fmt.Errorf("%s must not be negative (use 0 for unlimited)", v.name)
		}
	}
	return nil
}

func (c config) serverConfig() (serverConfig, error) {
	pat, err := compileRealmNamePattern(c.RealmNamePattern)
	if err != nil {
		return serverConfig{}, err
	}
	proxies, err := parseTrustedProxies(c.TrustedProxies)
	if err != nil {
		return serverConfig{}, err
	}
	if len(proxies) > 0 && c.TrustedProxyHeader == "" {
		return serverConfig{}, errors.New("trusted proxies are set, but no trusted proxy header is")
	}
	return serverConfig{
		maxRealms:        c.MaxRealms,
		maxRealmsPerIP:   c.MaxRealmsPerIP,
		connectRatePerIP: c.ConnectRatePerIP,
		proxyHeader:      c.TrustedProxyHeader,
		trustedProxies:   proxies,
		realmIDPattern:   pat,
	}, nil
}

// compileRealmNamePattern compiles pattern so that it has to match the whole
// realm name. Unanchored, a pattern like [a-z]+ would accept any name that
// merely contains a lowercase letter.
func compileRealmNamePattern(pattern string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(`^(?:` + pattern + `)$`)
	if err != nil {
		return nil, fmt.Errorf("invalid realm name pattern %q: %w", pattern, err)
	}
	return re, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvInt(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def, fmt.Errorf("%s: %q is not a whole number", k, v)
	}
	return n, nil
}

func getenvBool(k string, def bool) (bool, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "on":
		return true, nil
	case "no", "off":
		return false, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def, fmt.Errorf("%s: %q is not true or false", k, v)
	}
	return b, nil
}
