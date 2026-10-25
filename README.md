# libdns-opalstack

[libdns](https://github.com/libdns/libdns) provider for the
[Opalstack API](https://my.opalstack.com/api/v1/), plus a Caddy DNS module
wrapper (`caddy/`) exposing it as `dns.providers.opalstack` for solving ACME
DNS-01 challenges — i.e. wildcard certificates on domains whose DNS is hosted
at Opalstack.

Status: issuing wildcard certificates in production with Caddy v2.11 against
the live Opalstack API. Unit tests run against a mock built from the API spec.

## How it maps to Opalstack's model

Opalstack treats every hostname as its own Domain object; DNS records belong
to a Domain and carry no name. This provider:

- treats a libdns zone (`example.com.`) as "the Domain with that name plus
  every Domain ending in `.example.com`"
- finds-or-creates the Domain object for a record's FQDN on the fly
  (e.g. `_acme-challenge.example.com`)
- never deletes Domain objects (only records) — deleting a Domain a site or
  mailbox depends on would be destructive; leftover `_acme-challenge.*`
  Domains are harmless and get reused
- polls until changes report `READY` (Opalstack applies changes to its
  nameservers asynchronously); bounded by `propagation_timeout`, default 2m
- clamps TTL up to Opalstack's minimum of 300s

## Caddyfile usage

```
*.example.com {
	tls {
		dns opalstack {env.OPALSTACK_API_TOKEN}
		propagation_delay 1m
		propagation_timeout 10m
	}
	...
}
```

Optional block form: `api_token`, `api_url`, `propagation_timeout <dur>`.
That `propagation_timeout` bounds the provider's wait for `READY`; the two
lines under `dns` are Caddy's own `tls` options and govern its DNS
propagation check. Keep `propagation_delay` (see
[Opalstack API behaviour](#opalstack-api-behaviour)).

## Building Caddy with this module

```
xcaddy build --with github.com/bedz01/libdns-opalstack/caddy
```

The provider on its own, for other libdns consumers:

```
go get github.com/bedz01/libdns-opalstack
```

Developing both modules from a checkout: the `caddy/` module requires a
tagged release of the root module, so point Go at the local copy with a
workspace (`go work init . ./caddy`), or build Caddy with
`--with github.com/bedz01/libdns-opalstack/caddy=./caddy --replace github.com/bedz01/libdns-opalstack=.`

## Token scoping (recommended)

Opalstack tokens support ACLs (`/api/v1/tokenacl/`): create a dedicated token
and grant it only `read_domain`, `write_domain`, `read_dnsrecord`,
`write_dnsrecord`. `write_domain` is required because of the
Domain-per-hostname model above. Keep the powerful default token off the
server.

## Opalstack API behaviour

What the live API does, as far as this provider depends on it. The mock in
`provider_test.go` follows it.

- **Create and delete take JSON arrays**, as the official opalstack-python
  client sends them.
- **TXT content goes in unquoted** and is served exactly as sent.
- **Read endpoints have no trailing slash**: `/domain/read/{id}` and
  `/dnsrecord/read/{id}`. With a slash they return an HTML 404. List,
  create and delete endpoints do take the slash.
- **`READY` comes slightly before every nameserver serves the change.** A
  validation straight after `READY` can fail Let's Encrypt's multi-perspective
  check. Caddy's `propagation_delay 1m` covers it: production issuance
  validated first time with it.
- **Token ACLs are per object type, not per domain.** A token with
  `write_dnsrecord` can edit records on every domain in the account.

## Testing from a network that intercepts DNS

Some routers and ISPs answer all port-53 traffic themselves, whatever server
it is addressed to, and cache the replies. Caddy's propagation check then
reads that cache instead of Opalstack's nameservers, sees stale or negative
answers for up to the SOA's negative TTL (an hour), and times out. Check
first: `dig example.com @192.0.2.1` must time out, and an answer from
`ns1.sg.opalstack.com` must carry the `aa` flag. If not, test from a host
with a clean path.
