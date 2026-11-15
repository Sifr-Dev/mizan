package middleware

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPContextKey struct{}

// ClientIPMiddleware derives a client address without trusting forwarding
// headers from arbitrary peers. Forwarded headers are considered only when the
// immediate peer belongs to an explicitly configured trusted proxy range.
func ClientIPMiddleware(trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	prefixes := trustedProxyPrefixes(trustedProxies)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIPFromRequest(r, prefixes)
			ctx := context.WithValue(r.Context(), clientIPContextKey{}, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPContextKey{}).(string); ok && ip != "" {
		return ip
	}
	return remoteIP(r)
}

func clientIPFromRequest(r *http.Request, trustedProxies []netip.Prefix) string {
	remote, remoteOK := requestRemoteIP(r)
	if !remoteOK {
		return "unknown"
	}
	if !isTrustedProxy(remote, trustedProxies) {
		return remote.String()
	}

	// Walk the chain from the trusted edge toward the client. Selecting the
	// right-most untrusted address prevents an attacker-supplied left-most
	// X-Forwarded-For value from taking precedence.
	var candidates []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		candidates = append(candidates, strings.Split(value, ",")...)
	}
	for index := len(candidates) - 1; index >= 0; index-- {
		candidate := strings.TrimSpace(candidates[index])
		address, err := netip.ParseAddr(candidate)
		if err != nil {
			// A malformed trusted-proxy chain fails closed to the immediate
			// peer instead of selecting a less-trusted address.
			return remote.String()
		}
		address = address.Unmap()
		if isTrustedProxy(address, trustedProxies) {
			continue
		}
		return address.String()
	}

	return remote.String()
}

func requestRemoteIP(r *http.Request) (netip.Addr, bool) {
	if addressPort, err := netip.ParseAddrPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return addressPort.Addr().Unmap(), true
	}
	if address, err := netip.ParseAddr(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return address.Unmap(), true
	}
	return netip.Addr{}, false
}

func remoteIP(r *http.Request) string {
	address, ok := requestRemoteIP(r)
	if !ok {
		return "unknown"
	}
	return address.String()
}

func trustedProxyPrefixes(networks []*net.IPNet) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(networks))
	for _, network := range networks {
		if network == nil {
			continue
		}
		prefix, err := netip.ParsePrefix(network.String())
		if err != nil {
			continue
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func isTrustedProxy(address netip.Addr, trustedProxies []netip.Prefix) bool {
	if !address.IsValid() {
		return false
	}
	address = address.Unmap()
	for _, prefix := range trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
