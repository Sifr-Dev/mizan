package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const rateLimitScript = `
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if count == 1 or ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {count, ttl}
`

// RedisEvaler is the small part of the Redis client used by the limiter.
// Keeping the interface narrow makes the atomic script testable without a
// live Redis server.
type RedisEvaler interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

type RateLimiter struct {
	rdb        RedisEvaler
	maxReqs    int
	windowSize time.Duration
	failOpen   bool
	scope      string
}

type RateLimiterOption func(*RateLimiter)

func WithRateLimitFailOpen(failOpen bool) RateLimiterOption {
	return func(limiter *RateLimiter) {
		limiter.failOpen = failOpen
	}
}

func WithRateLimitScope(scope string) RateLimiterOption {
	return func(limiter *RateLimiter) {
		if strings.TrimSpace(scope) != "" {
			limiter.scope = scope
		}
	}
}

func WithRateLimitClient(client RedisEvaler) RateLimiterOption {
	return func(limiter *RateLimiter) {
		limiter.rdb = client
	}
}

func NewRateLimiter(rdb *redis.Client, maxReqs int, windowSize time.Duration, options ...RateLimiterOption) *RateLimiter {
	limiter := &RateLimiter{
		rdb:        rdb,
		maxReqs:    maxReqs,
		windowSize: windowSize,
		scope:      "api",
	}
	for _, option := range options {
		option(limiter)
	}
	return limiter
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS preflight requests do not reach an API handler and must not
		// consume the caller's request quota.
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if rl.rdb == nil {
			rl.handleUnavailable(w, r, next)
			return
		}

		scope := rl.safeScope()
		if strings.HasPrefix(r.URL.Path, "/api/v1/auth") {
			scope += ":auth"
		}
		key := "ratelimit:" + scope + ":" + ClientIP(r)
		result, err := rl.rdb.Eval(
			r.Context(),
			rateLimitScript,
			[]string{key},
			rl.windowSize.Milliseconds(),
		).Slice()
		if err != nil {
			rl.handleUnavailable(w, r, next)
			return
		}

		count, ok := numericResult(result, 0)
		if !ok {
			rl.handleUnavailable(w, r, next)
			return
		}
		ttlMilliseconds, ok := numericResult(result, 1)
		if !ok || ttlMilliseconds < 0 {
			ttlMilliseconds = rl.windowSize.Milliseconds()
		}

		remaining := rl.maxReqs - int(count)
		if remaining < 0 {
			remaining = 0
		}
		resetAt := time.Now().Add(time.Duration(ttlMilliseconds) * time.Millisecond).Unix()
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.maxReqs))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt, 10))

		if count > int64(rl.maxReqs) {
			retryAfter := int64((time.Duration(ttlMilliseconds)*time.Millisecond + time.Second - 1) / time.Second)
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
			writeRateLimitError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) handleUnavailable(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if rl.failOpen {
		slog.Warn("rate limiter unavailable; allowing request because fail-open is enabled")
		next.ServeHTTP(w, r)
		return
	}
	slog.Error("rate limiter unavailable; rejecting request because fail-closed is enabled")
	w.Header().Set("Retry-After", "1")
	writeRateLimitError(w, http.StatusServiceUnavailable, "rate limiter unavailable")
}

func (rl *RateLimiter) safeScope() string {
	scope := strings.TrimSpace(rl.scope)
	if scope == "" {
		return "api"
	}
	var builder strings.Builder
	for _, char := range scope {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

func numericResult(result []interface{}, index int) (int64, bool) {
	if index < 0 || index >= len(result) {
		return 0, false
	}
	switch value := result[index].(type) {
	case int64:
		return value, true
	case int:
		return int64(value), true
	case string:
		parsed, err := strconv.ParseInt(value, 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func writeRateLimitError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
