package main

import (
	"context"
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
	goproxy "github.com/stripe/goproxy"
)

// passthroughResolver skips real DNS (which is unavailable in this container).
// - If the host is already an IP, returns it as-is (used when connecting to upstream proxy).
// - Otherwise returns a public dummy IP (the upstream proxy handles the real connection).
type passthroughResolver struct{}

func (r *passthroughResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	// If the host is already an IP address, return it directly.
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	// Return a public dummy IP that passes Smokescreen's private-range check.
	return []net.IP{net.ParseIP("1.0.0.1")}, nil
}

func (r *passthroughResolver) LookupPort(_ context.Context, _, service string) (int, error) {
	switch service {
	case "https":
		return 443, nil
	case "http":
		return 80, nil
	default:
		return net.LookupPort("tcp", service)
	}
}

func main() {
	upstreamURL := os.Getenv("UPSTREAM_PROXY_URL")
	if upstreamURL != "" {
		// Set HTTP_PROXY so that Go's http.Transport forwards plain HTTP
		// requests through the upstream proxy WITH auth credentials.
		// (UpstreamHttpProxyAddr only takes host:port, no auth.)
		os.Setenv("HTTP_PROXY", upstreamURL)
		os.Setenv("HTTPS_PROXY", upstreamURL)
		os.Setenv("NO_PROXY", "")
	}

	conf, err := cmd.NewConfiguration(nil, nil)
	if err != nil {
		logrus.Fatalf("config: %v", err)
	}
	if conf == nil {
		return
	}

	// Accept every request as the "sandbox" role (no TLS client cert required).
	conf.RoleFromRequest = func(_ *http.Request) (string, error) {
		return "sandbox", nil
	}

	if upstreamURL != "" {
		u, err := url.Parse(upstreamURL)
		if err != nil {
			logrus.Fatalf("invalid UPSTREAM_PROXY_URL: %v", err)
		}

		hostPort := u.Host

		// Configure HTTPS upstream proxy for CONNECT tunnels.
		// Do NOT set UpstreamHttpProxyAddr — we let the HTTP_PROXY env var
		// handle plain HTTP proxying (it includes auth credentials).
		conf.UpstreamHttpsProxyAddr = hostPort

		// Use passthrough resolver (upstream proxy handles DNS).
		conf.Resolver = &passthroughResolver{}

		// Inject Proxy-Authorization for CONNECT requests to the upstream proxy.
		if u.User != nil {
			user := u.User.Username()
			pass, _ := u.User.Password()
			basicAuth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))

			conf.UpstreamProxyConnectReqHandler = func(_ *goproxy.ProxyCtx, req *http.Request) error {
				req.Header.Set("Proxy-Authorization", "Basic "+basicAuth)
				return nil
			}
		}
	}

	conf.Log.Formatter = &logrus.JSONFormatter{}
	adapter := &smokescreen.Log2LogrusWriter{
		Entry: conf.Log.WithField("stdlog", "1"),
	}
	log.SetOutput(adapter)
	log.SetFlags(0)

	smokescreen.StartWithConfig(conf, nil)
}
