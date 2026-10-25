// Package opalstack implements a DNS record management client compatible
// with the libdns interfaces for Opalstack (https://opalstack.com).
//
// Opalstack's data model differs from most providers: every hostname is its
// own Domain object (e.g. "www.example.com" and "_acme-challenge.example.com"
// are separate Domains), and DNS records belong to a Domain rather than
// carrying a name. This provider translates between that model and libdns
// zone-relative record names, creating Domain objects on demand. Domain
// objects created this way are intentionally never deleted (deleting a Domain
// a user relies on would be destructive); stale _acme-challenge Domains are
// harmless and are reused on the next issuance.
//
// Opalstack applies DNS changes to its nameservers asynchronously, so all
// mutating calls poll the API until the change reports READY (bounded by
// PropagationTimeout).
package opalstack

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Opalstack.
type Provider struct {
	// APIToken is an Opalstack API token ("Authorization: Token ..."). Use a
	// token restricted with Opalstack's token ACLs to DNS read/write only.
	APIToken string `json:"api_token,omitempty"`

	// APIURL overrides the API base URL (default https://my.opalstack.com/api/v1).
	APIURL string `json:"api_url,omitempty"`

	// PropagationTimeout bounds how long mutating calls wait for Opalstack to
	// report a change as READY on its nameservers. Default 2 minutes.
	PropagationTimeout time.Duration `json:"propagation_timeout,omitempty"`

	// mu serializes find-or-create of Domain objects so concurrent AppendRecords
	// calls do not race to create the same Domain.
	mu sync.Mutex
}

const (
	defaultPropagationTimeout = 2 * time.Minute
	minTTL                    = 300 // Opalstack API minimum
)

func (p *Provider) propagationTimeout() time.Duration {
	if p.PropagationTimeout > 0 {
		return p.PropagationTimeout
	}
	return defaultPropagationTimeout
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	domains, records, err := p.zoneState(ctx, zone)
	if err != nil {
		return nil, err
	}
	var out []libdns.Record
	for _, rec := range records {
		dom, ok := domains[rec.Domain]
		if !ok {
			continue
		}
		out = append(out, toLibdns(rec, dom.Name, zone))
	}
	return out, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	var creates []recordCreate
	var domainNames []string
	for _, rec := range recs {
		create, domainName, err := p.toCreate(ctx, zone, rec)
		if err != nil {
			return nil, err
		}
		creates = append(creates, create)
		domainNames = append(domainNames, domainName)
	}
	created, err := p.createRecords(ctx, creates)
	if err != nil {
		return nil, err
	}
	if err := p.waitRecordsReady(ctx, created); err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(created))
	for i, rec := range created {
		name := ""
		if i < len(domainNames) {
			name = domainNames[i]
		}
		out = append(out, toLibdns(rec, name, zone))
	}
	return out, nil
}

// SetRecords sets the records in the zone, either by updating existing records
// or creating new ones. For every (name, type) pair in the input, the records
// provided become the only members of that RRset in the zone.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	domains, existing, err := p.zoneState(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Collect the (name, type) pairs being set, then delete existing members.
	type rrsetKey struct{ name, typ string }
	sets := map[rrsetKey]bool{}
	for _, rec := range recs {
		rr := rec.RR()
		sets[rrsetKey{normalizeRelName(rr.Name, zone), rr.Type}] = true
	}
	var toDelete []string
	for _, rec := range existing {
		dom, ok := domains[rec.Domain]
		if !ok {
			continue
		}
		name := libdns.RelativeName(dom.Name+".", zone)
		if sets[rrsetKey{normalizeRelName(name, zone), rec.Type}] {
			toDelete = append(toDelete, rec.ID)
		}
	}
	if len(toDelete) > 0 {
		if err := p.deleteRecords(ctx, toDelete); err != nil {
			return nil, err
		}
	}
	return p.AppendRecords(ctx, zone, recs)
}

// DeleteRecords deletes records from the zone that exactly match the input.
// Empty Type, TTL, or Data fields in the input act as wildcards.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	domains, existing, err := p.zoneState(ctx, zone)
	if err != nil {
		return nil, err
	}
	var deleted []libdns.Record
	var ids []string
	for _, rec := range recs {
		want := rec.RR()
		wantName := normalizeRelName(want.Name, zone)
		for _, got := range existing {
			dom, ok := domains[got.Domain]
			if !ok {
				continue
			}
			gotRel := normalizeRelName(libdns.RelativeName(dom.Name+".", zone), zone)
			if gotRel != wantName {
				continue
			}
			if want.Type != "" && want.Type != got.Type {
				continue
			}
			if want.TTL != 0 && int(want.TTL.Seconds()) != got.TTL {
				continue
			}
			if want.Data != "" && !dataMatches(want, got) {
				continue
			}
			ids = append(ids, got.ID)
			deleted = append(deleted, toLibdns(got, dom.Name, zone))
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	if err := p.deleteRecords(ctx, ids); err != nil {
		return nil, err
	}
	return deleted, nil
}

// zoneState fetches the account's Domains belonging to zone (apex or any
// hostname under it) keyed by UUID, plus all DNS records referencing them.
func (p *Provider) zoneState(ctx context.Context, zone string) (map[string]opalDomain, []opalRecord, error) {
	zoneName := strings.TrimSuffix(strings.ToLower(zone), ".")
	if zoneName == "" {
		return nil, nil, fmt.Errorf("empty zone")
	}
	allDomains, err := p.listDomains(ctx)
	if err != nil {
		return nil, nil, err
	}
	domains := map[string]opalDomain{}
	for _, d := range allDomains {
		name := strings.ToLower(d.Name)
		if name == zoneName || strings.HasSuffix(name, "."+zoneName) {
			domains[d.ID] = d
		}
	}
	allRecords, err := p.listRecords(ctx)
	if err != nil {
		return nil, nil, err
	}
	var records []opalRecord
	for _, r := range allRecords {
		if _, ok := domains[r.Domain]; ok {
			records = append(records, r)
		}
	}
	return domains, records, nil
}

// toCreate converts a libdns record into an Opalstack create payload,
// finding or creating the Domain object the record must attach to.
func (p *Provider) toCreate(ctx context.Context, zone string, rec libdns.Record) (recordCreate, string, error) {
	rr := rec.RR()
	fqdn := strings.TrimSuffix(strings.ToLower(libdns.AbsoluteName(rr.Name, zone)), ".")
	dom, err := p.findOrCreateDomain(ctx, fqdn)
	if err != nil {
		return recordCreate{}, "", err
	}

	create := recordCreate{
		Domain: dom.ID,
		Type:   rr.Type,
		TTL:    ttlSeconds(rr.TTL),
	}
	switch r := rec.(type) {
	case libdns.TXT:
		create.Content = r.Text
	case libdns.MX:
		create.Priority = int(r.Preference)
		create.Content = strings.TrimSuffix(r.Target, ".")
	case libdns.CNAME:
		create.Content = strings.TrimSuffix(r.Target, ".")
	case libdns.Address:
		create.Content = r.IP.String()
	default:
		// Opaque RR: for priority-carrying types, split the leading integer.
		data := rr.Data
		if rr.Type == "MX" || rr.Type == "SRV" {
			if fields := strings.Fields(data); len(fields) > 1 {
				if prio, err := strconv.Atoi(fields[0]); err == nil {
					create.Priority = prio
					data = strings.Join(fields[1:], " ")
				}
			}
		}
		create.Content = data
	}
	return create, dom.Name, nil
}

func (p *Provider) findOrCreateDomain(ctx context.Context, fqdn string) (opalDomain, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	domains, err := p.listDomains(ctx)
	if err != nil {
		return opalDomain{}, err
	}
	for _, d := range domains {
		if strings.EqualFold(d.Name, fqdn) {
			return d, nil
		}
	}
	dom, err := p.createDomain(ctx, fqdn)
	if err != nil {
		return opalDomain{}, err
	}
	err = waitReady(ctx, p.propagationTimeout(), func(ctx context.Context) (bool, error) {
		d, err := p.readDomain(ctx, dom.ID)
		return d.Ready, err
	})
	return dom, err
}

func (p *Provider) waitRecordsReady(ctx context.Context, recs []opalRecord) error {
	for _, rec := range recs {
		rec := rec
		err := waitReady(ctx, p.propagationTimeout(), func(ctx context.Context) (bool, error) {
			r, err := p.readRecord(ctx, rec.ID)
			return r.Ready, err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// toLibdns converts an Opalstack record (plus its owning Domain's name) into a
// typed libdns record.
func toLibdns(rec opalRecord, domainName, zone string) libdns.Record {
	name := "@"
	if domainName != "" {
		name = libdns.RelativeName(strings.ToLower(domainName)+".", zone)
	}
	data := rec.Content
	if rec.Type == "MX" || rec.Type == "SRV" {
		data = fmt.Sprintf("%d %s", rec.Priority, rec.Content)
	}
	rr := libdns.RR{
		Name: name,
		TTL:  time.Duration(rec.TTL) * time.Second,
		Type: rec.Type,
		Data: data,
	}
	if parsed, err := rr.Parse(); err == nil {
		return parsed
	}
	return rr
}

// dataMatches compares a libdns RR's data against an Opalstack record,
// accounting for the priority being a separate field at Opalstack.
func dataMatches(want libdns.RR, got opalRecord) bool {
	gotData := got.Content
	if got.Type == "MX" || got.Type == "SRV" {
		gotData = fmt.Sprintf("%d %s", got.Priority, got.Content)
	}
	return strings.TrimSuffix(want.Data, ".") == strings.TrimSuffix(gotData, ".")
}

func normalizeRelName(name, zone string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "@" {
		return "@"
	}
	// Tolerate absolute names in input.
	rel := libdns.RelativeName(name, zone)
	if rel == "" {
		return "@"
	}
	return strings.TrimSuffix(rel, ".")
}

func ttlSeconds(ttl time.Duration) int {
	secs := int(ttl.Seconds())
	if secs < minTTL {
		return minTTL
	}
	return secs
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
