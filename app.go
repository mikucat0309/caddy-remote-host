package caddy_remote_host

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("remote_host", parseRemoteHostApp)
	caddy.RegisterModule(&MatchRemoteHostApp{})
}

const (
	DefaultRefreshInterval = time.Minute
	DefaultRefreshTimeout  = 5 * time.Second
)

// MatchRemoteHostApp maintains an IP set for each configured hostname,
// periodically resolving them so HTTP matchers can verify that the
// client's IP belongs to a host.
type MatchRemoteHostApp struct {
	// How often hostnames are re-resolved. Default 1m.
	RefreshInterval caddy.Duration `json:"refresh_interval,omitempty"`

	// Deadline for each refresh cycle; lookups of one cycle never
	// overlap the next. Default 5s.
	RefreshTimeout caddy.Duration `json:"refresh_timeout,omitempty"`

	// Addresses of upstream DNS servers, e.g. udp/1.1.1.1:53.
	// If unset, the system resolver is used (same as Caddy itself).
	Resolver []string `json:"resolver,omitempty"`

	logger   *zap.Logger
	resolver *net.Resolver
	interval time.Duration
	timeout  time.Duration

	hosts map[string]*Host

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (a *MatchRemoteHostApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "remote_host",
		New: func() caddy.Module { return new(MatchRemoteHostApp) },
	}
}

func (a *MatchRemoteHostApp) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()

	a.interval = time.Duration(a.RefreshInterval)
	if a.interval == 0 {
		a.interval = DefaultRefreshInterval
	}

	a.timeout = time.Duration(a.RefreshTimeout)
	if a.timeout == 0 {
		a.timeout = DefaultRefreshTimeout
	}

	if a.hosts == nil {
		a.hosts = make(map[string]*Host)
	}

	if len(a.Resolver) == 0 {
		a.resolver = net.DefaultResolver // same system path Caddy uses itself
		return nil
	}

	var netAddrs []caddy.NetworkAddress
	for _, addr := range a.Resolver {
		parsed, err := caddy.ParseNetworkAddressWithDefaults(addr, "udp", 53)
		if err != nil {
			return fmt.Errorf("parsing resolver address %q: %v", addr, err)
		}
		netAddrs = append(netAddrs, parsed)
	}
	dialer := &net.Dialer{Timeout: a.timeout}
	a.resolver = &net.Resolver{
		PreferGo: true, // custom resolvers require the Go resolver; mirrors reverseproxy upstreams
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			addr := netAddrs[rand.IntN(len(netAddrs))]
			return dialer.DialContext(ctx, addr.Network, addr.JoinHostPort(0))
		},
	}

	return nil
}

func (a *MatchRemoteHostApp) Validate() error {
	if a.RefreshInterval < 0 {
		return fmt.Errorf("refresh_interval must be non-negative, got %v", time.Duration(a.RefreshInterval))
	}
	if a.RefreshTimeout < 0 {
		return fmt.Errorf("refresh_timeout must be non-negative, got %v", time.Duration(a.RefreshTimeout))
	}
	for _, addr := range a.Resolver {
		parsed, err := caddy.ParseNetworkAddressWithDefaults(addr, "udp", 53)
		if err != nil {
			return fmt.Errorf("parsing resolver address %q: %v", addr, err)
		}
		if parsed.PortRangeSize() != 1 {
			return fmt.Errorf("resolver address must specify exactly one port; cannot use %v", parsed)
		}
	}
	return nil
}

func (a *MatchRemoteHostApp) Start() error {
	initCtx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	a.refreshAll(initCtx)

	a.ctx, a.cancel = context.WithCancel(context.Background())
	a.wg.Add(1)
	go a.loop()
	return nil
}

func (a *MatchRemoteHostApp) Stop() error {
	if a.cancel != nil {
		a.cancel()
		a.wg.Wait()
	}
	return nil
}

func (a *MatchRemoteHostApp) loop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			cycleCtx, cancel := context.WithTimeout(a.ctx, a.timeout)
			a.refreshAll(cycleCtx)
			cancel()
		}
	}
}

func (a *MatchRemoteHostApp) refreshAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, h := range a.hosts {
		wg.Go(func() {
			h.refresh(ctx, a.resolver, a.logger)
		})
	}
	wg.Wait()
}

func (a *MatchRemoteHostApp) host(hostname string) *Host {
	h, ok := a.hosts[hostname]
	if !ok {
		h = newHost(hostname)
		a.hosts[hostname] = h
	}
	return h
}

type Host struct {
	host string
	addrs atomic.Pointer[map[netip.Addr]struct{}]
}

func newHost(hostname string) *Host {
	h := &Host{host: hostname}
	m := make(map[netip.Addr]struct{})
	h.addrs.Store(&m)
	return h
}

func (h *Host) Contains(addr netip.Addr) bool {
	m := h.addrs.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[canonicalAddr(addr)]
	return ok
}

func (h *Host) refresh(ctx context.Context, resolver *net.Resolver, logger *zap.Logger) {
	fresh := make(map[netip.Addr]struct{})
	addrs, err := resolver.LookupNetIP(ctx, "ip", h.host)
	if err != nil {
		if c := logger.Check(zapcore.WarnLevel, "hostname lookup failed; host will not match until resolution succeeds"); c != nil {
			c.Write(zap.String("host", h.host), zap.Error(err))
		}
	} else {
		cAddrs := make([]netip.Addr, 0, len(addrs))
		for _, addr := range addrs {
			cAddrs = append(cAddrs, canonicalAddr(addr))
		}
		for _, cAddr := range cAddrs {
			fresh[cAddr] = struct{}{}
		}
		if c := logger.Check(zapcore.DebugLevel, "hostname lookup success"); c != nil {
			strings := make([]string, 0, len(cAddrs))
			for _, addr := range cAddrs {
				strings = append(strings, addr.String())
			}
			c.Write(zap.String("host", h.host), zap.Strings("addrs", strings))
		}
	}
	h.addrs.Store(&fresh)
}

// strips zones and unmaps IPv4-mapped IPv6 addresses.
func canonicalAddr(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	return addr.WithZone("")
}

//	remote_host {
//	    refresh_interval 60s
//	    refresh_timeout 5s
//	    resolver 1.1.1.1:53 tcp/8.8.8.8:53
//	}
func (a *MatchRemoteHostApp) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "refresh_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid refresh_interval %q: %v", d.Val(), err)
				}
				a.RefreshInterval = caddy.Duration(dur)
			case "refresh_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid refresh_timeout %q: %v", d.Val(), err)
				}
				a.RefreshTimeout = caddy.Duration(dur)
			case "resolver":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				a.Resolver = append(a.Resolver, args...)
			default:
				return d.Errf("unrecognized subdirective %q", d.Val())
			}
		}
	}
	return nil
}

func parseRemoteHostApp(d *caddyfile.Dispenser, _ any) (any, error) {
	app := new(MatchRemoteHostApp)
	err := app.UnmarshalCaddyfile(d)
	if err != nil {
		return nil, err
	}
	return httpcaddyfile.App{
		Name:  "remote_host",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

// Interface guards
var (
	_ caddy.App             = (*MatchRemoteHostApp)(nil)
	_ caddy.Provisioner     = (*MatchRemoteHostApp)(nil)
	_ caddy.Validator       = (*MatchRemoteHostApp)(nil)
	_ caddyfile.Unmarshaler = (*MatchRemoteHostApp)(nil)
)
