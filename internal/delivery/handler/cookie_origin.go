package handler

import (
	"net/http"
	"net/url"
	"strings"
)

// cookieRequestOriginAllowed protects the cookie-authenticated refresh and
// logout endpoints from cross-site requests. SameSite is the primary defense;
// Origin validation adds an explicit allowlist check for cross-origin browser
// clients. A request without Origin is accepted only when SameSite=None is not
// in use, preserving support for non-browser clients and command-line tools.
func (h *UserHandler) cookieRequestOriginAllowed(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return h.refreshCookie.SameSite != http.SameSiteNoneMode
	}
	if len(origins) != 1 {
		return false
	}

	origin, originHost, ok := normalizeOrigin(origins[0])
	if !ok {
		return false
	}
	for _, allowed := range h.refreshCookie.AllowedOrigins {
		normalized, _, valid := normalizeOrigin(allowed)
		if valid && normalized == origin {
			return true
		}
	}

	// Same-origin browser requests use the public Host value. Scheme is not
	// compared because TLS termination commonly occurs before this handler.
	return originHost != "" && strings.EqualFold(originHost, r.Host)
}

func normalizeOrigin(raw string) (origin string, host string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", false
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Path = ""
	return parsed.String(), parsed.Host, true
}
