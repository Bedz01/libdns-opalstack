// Package opalstack registers the Opalstack libdns provider as the Caddy
// module dns.providers.opalstack, for solving ACME DNS-01 challenges.
package opalstack

import (
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	opalstack "github.com/bedz01/libdns-opalstack"
)

func init() {
	caddy.RegisterModule(Provider{})
}

// Provider wraps the libdns Opalstack provider as a Caddy module.
type Provider struct{ *opalstack.Provider }

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.opalstack",
		New: func() caddy.Module { return &Provider{new(opalstack.Provider)} },
	}
}

// Provision implements caddy.Provisioner, resolving placeholders like {env.*}.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.Provider.APIToken = repl.ReplaceAll(p.Provider.APIToken, "")
	p.Provider.APIURL = repl.ReplaceAll(p.Provider.APIURL, "")
	return nil
}

// UnmarshalCaddyfile sets up the provider from Caddyfile tokens. Syntax:
//
//	opalstack [<api_token>] {
//	    api_token <api_token>
//	    api_url <base_url>
//	    propagation_timeout <duration>
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			p.Provider.APIToken = d.Val()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "api_token":
				if p.Provider.APIToken != "" {
					return d.Err("api_token already set")
				}
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Provider.APIToken = d.Val()
			case "api_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Provider.APIURL = d.Val()
			case "propagation_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid propagation_timeout: %v", err)
				}
				p.Provider.PropagationTimeout = dur
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.Provider.APIToken == "" {
		return d.Err("missing api_token")
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)
