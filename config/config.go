package config

import (
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type (
	Config struct {
		App       AppConfig       `yaml:"app"`
		HTTP      HTTPConfig      `yaml:"http"`
		Log       LogConfig       `yaml:"log"`
		DB        DBConfig        `yaml:"db"`
		Redis     RedisConfig     `yaml:"redis"`
		JWT       JWTConfig       `yaml:"jwt"`
		CORS      CORSConfig      `yaml:"cors"`
		RateLimit RateLimitConfig `yaml:"rate_limit"`
		Request   RequestConfig   `yaml:"request"`
		Auth      AuthConfig      `yaml:"auth"`
	}

	AppConfig struct {
		Name    string `env-required:"true" yaml:"name" env:"APP_NAME"`
		Version string `env-required:"true" yaml:"version" env:"APP_VERSION"`
		Env     string `env-required:"true" yaml:"env" env:"APP_ENV"` // local, dev, prod
	}

	HTTPConfig struct {
		Port            string        `env-required:"true" yaml:"port" env:"HTTP_PORT"`
		ReadTimeout     time.Duration `env-required:"true" yaml:"read_timeout" env:"HTTP_READ_TIMEOUT"`
		WriteTimeout    time.Duration `env-required:"true" yaml:"write_timeout" env:"HTTP_WRITE_TIMEOUT"`
		ShutdownTimeout time.Duration `env-required:"true" yaml:"shutdown_timeout" env:"HTTP_SHUTDOWN_TIMEOUT"`
	}

	LogConfig struct {
		Level string `env-required:"true" yaml:"level" env:"LOG_LEVEL"` // debug, info, warn, error
	}

	DBConfig struct {
		URL             string        `env-required:"true" yaml:"url" env:"DATABASE_URL"`
		MaxConns        int32         `env-default:"10" yaml:"max_conns" env:"DB_MAX_CONNS"`
		MinConns        int32         `env-default:"2" yaml:"min_conns" env:"DB_MIN_CONNS"`
		MaxConnIdleTime time.Duration `env-default:"15m" yaml:"max_conn_idle_time" env:"DB_MAX_CONN_IDLE_TIME"`
		MaxConnLifeTime time.Duration `env-default:"1h" yaml:"max_conn_lifetime" env:"DB_MAX_CONN_LIFETIME"`
	}

	RedisConfig struct {
		URL string `env-required:"true" yaml:"url" env:"REDIS_URL"`
	}

	JWTConfig struct {
		Secret            string        `env-required:"true" yaml:"secret" env:"JWT_SECRET"`
		Issuer            string        `env-default:"go-clean-api" yaml:"issuer" env:"JWT_ISSUER"`
		Audience          string        `env-default:"go-clean-api-client" yaml:"audience" env:"JWT_AUDIENCE"`
		AccessExpiration  time.Duration `env-required:"true" yaml:"access_expiration" env:"JWT_ACCESS_EXPIRATION"`
		RefreshExpiration time.Duration `env-required:"true" yaml:"refresh_expiration" env:"JWT_REFRESH_EXPIRATION"`
	}

	CORSConfig struct {
		AllowedOrigins string `env-default:"" yaml:"allowed_origins" env:"CORS_ALLOWED_ORIGINS"`
	}

	RateLimitConfig struct {
		MaxRequests       int           `env-default:"100" yaml:"max_requests" env:"RATE_LIMIT_MAX_REQUESTS"`
		Window            time.Duration `env-default:"1m" yaml:"window" env:"RATE_LIMIT_WINDOW"`
		FailOpen          bool          `env-default:"false" yaml:"fail_open" env:"RATE_LIMIT_FAIL_OPEN"`
		TrustedProxyCIDRs string        `env-default:"" yaml:"trusted_proxy_cidrs" env:"TRUSTED_PROXY_CIDRS"`
		Scope             string        `env-default:"api" yaml:"scope" env:"RATE_LIMIT_SCOPE"`
	}

	RequestConfig struct {
		MaxBodyBytes int64 `env-default:"1048576" yaml:"max_body_bytes" env:"REQUEST_MAX_BODY_BYTES"`
	}

	AuthConfig struct {
		CookieName     string `env-default:"refresh_token" yaml:"cookie_name" env:"AUTH_COOKIE_NAME"`
		CookiePath     string `env-default:"/api/v1/auth" yaml:"cookie_path" env:"AUTH_COOKIE_PATH"`
		CookieSecure   bool   `env-default:"false" yaml:"cookie_secure" env:"AUTH_COOKIE_SECURE"`
		CookieSameSite string `env-default:"strict" yaml:"cookie_same_site" env:"AUTH_COOKIE_SAME_SITE"`
	}

	// AdminConfig is intentionally separate from the application config. The
	// API never creates or promotes an administrator implicitly; the explicit
	// provisioning command reads these values when an owner asks for it.
	AdminConfig struct {
		DatabaseURL string `env-required:"true" yaml:"database_url" env:"DATABASE_URL"`
		Email       string `env-required:"true" yaml:"email" env:"ADMIN_EMAIL"`
		Password    string `env-required:"true" yaml:"password" env:"ADMIN_PASSWORD"`
		Name        string `env-default:"Administrator" yaml:"name" env:"ADMIN_NAME"`
	}
)

const (
	minimumJWTSecretBytes      = 32
	minimumAdminPasswordBytes  = 12
	minimumAdminPasswordRunes  = 12
	maximumBcryptPasswordBytes = 72
	maximumAdminNameRunes      = 100
	maximumEmailLength         = 255
)

// LoadConfig loads config from environment variables and/or optional .env file.
func LoadConfig() (*Config, error) {
	cfg := &Config{}
	if err := readConfig(".env", cfg); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	return cfg, nil
}

// LoadAdminConfig loads only the values needed by the explicit administrator
// provisioning command. It never reads a default password or promotes an
// existing account.
func LoadAdminConfig() (*AdminConfig, error) {
	cfg := &AdminConfig{}
	if err := readConfig(".env", cfg); err != nil {
		return nil, fmt.Errorf("failed to load admin config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// readConfig gives explicitly injected environment variables precedence over
// values in .env. A .env file may fill missing local-development values, but it
// cannot replace a secret or production setting supplied by the process
// environment. Production processes do not read .env at all.
func readConfig(path string, cfg interface{}) error {
	if !isProduction(os.Getenv("APP_ENV")) {
		if _, err := os.Stat(path); err == nil {
			values, err := godotenv.Read(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			effectiveEnv := values["APP_ENV"]
			if injectedEnv, exists := os.LookupEnv("APP_ENV"); exists {
				effectiveEnv = injectedEnv
			}
			if !isProduction(effectiveEnv) {
				for key, value := range values {
					if _, exists := os.LookupEnv(key); exists {
						continue
					}
					if err := os.Setenv(key, value); err != nil {
						return fmt.Errorf("set %s from %s: %w", key, path, err)
					}
				}
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", path, err)
		}
	}
	return cleanenv.ReadEnv(cfg)
}

// Validate rejects unsafe runtime configuration before the application opens
// network listeners or connects to production services.
func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if strings.TrimSpace(c.App.Env) == "" {
		return fmt.Errorf("APP_ENV is required")
	}
	if len(c.JWT.Secret) < minimumJWTSecretBytes {
		return fmt.Errorf("JWT_SECRET must be at least %d bytes", minimumJWTSecretBytes)
	}
	if strings.TrimSpace(c.JWT.Issuer) == "" || strings.TrimSpace(c.JWT.Audience) == "" {
		return fmt.Errorf("JWT_ISSUER and JWT_AUDIENCE are required")
	}
	if c.JWT.AccessExpiration <= 0 || c.JWT.RefreshExpiration <= 0 {
		return fmt.Errorf("JWT expiration durations must be positive")
	}
	if c.JWT.RefreshExpiration <= c.JWT.AccessExpiration {
		return fmt.Errorf("JWT_REFRESH_EXPIRATION must be longer than JWT_ACCESS_EXPIRATION")
	}
	if c.RateLimit.MaxRequests <= 0 || c.RateLimit.Window <= 0 {
		return fmt.Errorf("rate-limit values must be positive")
	}
	if strings.TrimSpace(c.RateLimit.Scope) == "" {
		return fmt.Errorf("RATE_LIMIT_SCOPE is required")
	}
	if c.Request.MaxBodyBytes <= 0 {
		return fmt.Errorf("REQUEST_MAX_BODY_BYTES must be positive")
	}
	if _, err := c.CORSOrigins(); err != nil {
		return err
	}
	if _, err := c.TrustedProxyCIDRs(); err != nil {
		return err
	}
	sameSite, err := c.SameSiteMode()
	if err != nil {
		return err
	}
	if sameSite == http.SameSiteNoneMode && !c.Auth.CookieSecure {
		return fmt.Errorf("AUTH_COOKIE_SECURE must be true when AUTH_COOKIE_SAME_SITE=none")
	}
	if strings.TrimSpace(c.Auth.CookieName) == "" || !strings.HasPrefix(c.Auth.CookiePath, "/") {
		return fmt.Errorf("auth cookie name and absolute cookie path are required")
	}
	if isProduction(c.App.Env) && !c.Auth.CookieSecure {
		return fmt.Errorf("AUTH_COOKIE_SECURE must be true in production")
	}
	return nil
}

func (c *Config) CORSOrigins() ([]string, error) {
	parts := strings.Split(c.CORS.AllowedOrigins, ",")
	origins := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		origin := strings.TrimSpace(part)
		if origin == "" {
			continue
		}
		if strings.Contains(origin, "*") {
			return nil, fmt.Errorf("CORS_ALLOWED_ORIGINS must not contain wildcards")
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("invalid CORS origin %q", origin)
		}
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = strings.ToLower(parsed.Host)
		parsed.Path = ""
		origin = parsed.String()
		if isProduction(c.App.Env) && parsed.Scheme != "https" {
			return nil, fmt.Errorf("CORS origin %q must use HTTPS in production", origin)
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	return origins, nil
}

func (c *Config) TrustedProxyCIDRs() ([]*net.IPNet, error) {
	parts := strings.Split(c.RateLimit.TrustedProxyCIDRs, ",")
	networks := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", value, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func (c *Config) SameSiteMode() (http.SameSite, error) {
	switch strings.ToLower(strings.TrimSpace(c.Auth.CookieSameSite)) {
	case "", "strict":
		return http.SameSiteStrictMode, nil
	case "lax":
		return http.SameSiteLaxMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return http.SameSiteDefaultMode, fmt.Errorf("AUTH_COOKIE_SAME_SITE must be strict, lax, or none")
	}
}

func (c *AdminConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("admin config is nil")
	}
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if err := validateAdminEmail(c.Email); err != nil {
		return err
	}
	if len([]byte(c.Password)) < minimumAdminPasswordBytes || utf8.RuneCountInString(c.Password) < minimumAdminPasswordRunes {
		return fmt.Errorf("ADMIN_PASSWORD must be at least %d characters and %d bytes", minimumAdminPasswordRunes, minimumAdminPasswordBytes)
	}
	if len([]byte(c.Password)) > maximumBcryptPasswordBytes {
		return fmt.Errorf("ADMIN_PASSWORD must not exceed %d bytes", maximumBcryptPasswordBytes)
	}
	name := strings.TrimSpace(c.Name)
	if name == "" || utf8.RuneCountInString(name) > maximumAdminNameRunes {
		return fmt.Errorf("ADMIN_NAME must contain between 1 and %d characters", maximumAdminNameRunes)
	}
	return nil
}

func validateAdminEmail(email string) error {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if normalized == "" || len(normalized) > maximumEmailLength {
		return fmt.Errorf("ADMIN_EMAIL is invalid")
	}
	parsed, err := mail.ParseAddress(normalized)
	if err != nil || parsed.Name != "" || parsed.Address != normalized {
		return fmt.Errorf("ADMIN_EMAIL is invalid")
	}
	return nil
}

func isProduction(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "prod", "production":
		return true
	default:
		return false
	}
}
