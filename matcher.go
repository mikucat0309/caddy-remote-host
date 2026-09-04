package caddy_remote_host

import (
	"fmt"
	"net/http"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(MatchRemoteHost{})
}

type MatchRemoteHost struct {
	Hosts  []string `json:"hosts,omitempty"`
	hosts  []*Host
	logger *zap.Logger
}

func (MatchRemoteHost) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.remote_host",
		New: func() caddy.Module { return new(MatchRemoteHost) },
	}
}

func (m *MatchRemoteHost) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// iterate to merge multiple matchers into one
	for d.Next() {
		for d.NextArg() {
			m.Hosts = append(m.Hosts, d.Val())
		}
		if d.NextBlock(0) {
			return d.Err("malformed remote_host matcher: blocks are not supported")
		}
	}
	return nil
}

func (m *MatchRemoteHost) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	v, err := ctx.App("remote_host")
	if err != nil {
		return fmt.Errorf("getting remote_host app: %v", err)
	}
	app, ok := v.(*MatchRemoteHostApp)
	if !ok {
		return fmt.Errorf("remote_host app is of unexpected type %T", v)
	}
	for _, hostname := range m.Hosts {
		m.hosts = append(m.hosts, app.host(hostname))
	}
	return nil
}

func (m *MatchRemoteHost) Validate() error {
	if len(m.Hosts) == 0 {
		return fmt.Errorf("remote_host matcher requires at least one hostname")
	}
	return nil
}

// MatchWithError returns true if r matches m.
// copied from https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/ip_matchers.go
func (m MatchRemoteHost) MatchWithError(r *http.Request) (bool, error) {
	// if handshake is not finished, we infer 0-RTT that has
	// not verified remote IP; could be spoofed, so we throw
	// HTTP 425 status to tell the client to try again after
	// the handshake is complete
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return false, caddyhttp.Error(http.StatusTooEarly, fmt.Errorf("TLS handshake not complete, remote IP cannot be verified"))
	}

	addr, err := parseIP(r.RemoteAddr)
	if err != nil {
		if c := m.logger.Check(zapcore.ErrorLevel, "invalid client IP address"); c != nil {
			c.Write(zap.Error(err))
		}

		return false, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid client IP address: %s", r.RemoteAddr))
	}
	for _, h := range m.hosts {
		if h.Contains(addr) {
			return true, nil
		}
	}
	return false, nil
}

func parseIP(s string) (netip.Addr, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.IPv4Unspecified(), err
	}
	return addrPort.Addr(), nil
}

// Interface guards
var (
	_ caddyhttp.RequestMatcherWithError = (*MatchRemoteHost)(nil)
	_ caddy.Provisioner                 = (*MatchRemoteHost)(nil)
	_ caddy.Validator                   = (*MatchRemoteHost)(nil)
	_ caddyfile.Unmarshaler             = (*MatchRemoteHost)(nil)
)
