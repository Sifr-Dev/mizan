package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() *Config {
	return &Config{
		App: AppConfig{Env: "local"},
		JWT: JWTConfig{
			Secret:            strings.Repeat("s", 32),
			Issuer:            "issuer",
			Audience:          "audience",
			AccessExpiration:  15 * time.Minute,
			RefreshExpiration: 24 * time.Hour,
		},
		RateLimit: RateLimitConfig{MaxRequests: 10, Window: time.Minute, Scope: "api"},
		Request:   RequestConfig{MaxBodyBytes: 1024},
		Auth:      AuthConfig{CookieName: "refresh_token", CookiePath: "/api/v1/auth", CookieSameSite: "strict"},
	}
}

func TestConfigRejectsWeakOrUnsafeValues(t *testing.T) {
	config := validConfig()
	config.JWT.Secret = "short"
	assert.Error(t, config.Validate())

	config = validConfig()
	config.CORS.AllowedOrigins = "*"
	assert.Error(t, config.Validate())

	config = validConfig()
	config.CORS.AllowedOrigins = "https://*.example.com"
	assert.Error(t, config.Validate())

	config = validConfig()
	config.RateLimit.TrustedProxyCIDRs = "not-a-cidr"
	assert.Error(t, config.Validate())

	config = validConfig()
	config.App.Env = "production"
	assert.Error(t, config.Validate())

	config = validConfig()
	config.Auth.CookieSameSite = "none"
	assert.Error(t, config.Validate())
}

func TestConfigCORSOriginsAreExplicitAndNormalized(t *testing.T) {
	config := validConfig()
	config.CORS.AllowedOrigins = "http://localhost:3000/, https://APP.example.com,http://localhost:3000"

	origins, err := config.CORSOrigins()
	require.NoError(t, err)
	assert.Equal(t, []string{"http://localhost:3000", "https://app.example.com"}, origins)
}

func TestConfigRequiresHTTPSForProductionOrigins(t *testing.T) {
	config := validConfig()
	config.App.Env = "production"
	config.Auth.CookieSecure = true
	config.CORS.AllowedOrigins = "http://app.example.com"

	_, err := config.CORSOrigins()
	assert.Error(t, err)
}

func TestAdminConfigRequiresExplicitStrongPasswordAndPlainEmail(t *testing.T) {
	config := &AdminConfig{
		DatabaseURL: "postgres://localhost/db",
		Email:       "admin@example.com",
		Password:    "short",
		Name:        "Owner",
	}
	assert.Error(t, config.Validate())

	config.Password = strings.Repeat("p", 12)
	assert.NoError(t, config.Validate())

	config.Email = "Owner <admin@example.com>"
	assert.Error(t, config.Validate())

	config.Email = "admin@example.com"
	config.Password = strings.Repeat("é", 6)
	assert.Error(t, config.Validate())
}

type injectedConfig struct {
	Value string `env-required:"true" env:"GO_DB_CONFIG_PRECEDENCE_TEST"`
}

func TestReadConfigDoesNotOverwriteInjectedEnvironment(t *testing.T) {
	t.Setenv("GO_DB_CONFIG_PRECEDENCE_TEST", "from-environment")
	path := filepath.Join(t.TempDir(), ".env")
	require.NoError(t, os.WriteFile(path, []byte("GO_DB_CONFIG_PRECEDENCE_TEST=from-file\n"), 0o600))

	var cfg injectedConfig
	require.NoError(t, readConfig(path, &cfg))
	assert.Equal(t, "from-environment", cfg.Value)
}

func TestReadConfigIgnoresDotenvWhenFileSelectsProduction(t *testing.T) {
	unsetEnvironment(t, "APP_ENV")
	path := filepath.Join(t.TempDir(), ".env")
	require.NoError(t, os.WriteFile(path, []byte("APP_ENV=production\nGO_DB_CONFIG_PRECEDENCE_TEST=from-file\n"), 0o600))

	var cfg injectedConfig
	assert.Error(t, readConfig(path, &cfg))
}

func unsetEnvironment(t *testing.T, key string) {
	t.Helper()
	previous, existed := os.LookupEnv(key)
	require.NoError(t, os.Unsetenv(key))
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(key, previous)
			return
		}
		_ = os.Unsetenv(key)
	})
}

func TestReadConfigIgnoresDotenvInProduction(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	path := filepath.Join(t.TempDir(), ".env")
	require.NoError(t, os.WriteFile(path, []byte("GO_DB_CONFIG_PRECEDENCE_TEST=from-file\n"), 0o600))

	var cfg injectedConfig
	assert.Error(t, readConfig(path, &cfg))
}
