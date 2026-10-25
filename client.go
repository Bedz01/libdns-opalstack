package opalstack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultAPIURL = "https://my.opalstack.com/api/v1"

// opalDomain is a Domain object in the Opalstack API. Opalstack models every
// hostname (e.g. "_acme-challenge.example.com") as its own Domain; DNS records
// reference the Domain by UUID and carry no name of their own.
type opalDomain struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
	Ready bool   `json:"ready"`
}

// opalRecord is a DNSRecord object in the Opalstack API.
type opalRecord struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"` // Domain UUID
	Type     string `json:"type"`
	Content  string `json:"content"`
	Priority int    `json:"priority,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	State    string `json:"state,omitempty"`
	Ready    bool   `json:"ready,omitempty"`
}

type recordCreate struct {
	Domain   string `json:"domain"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	Priority int    `json:"priority,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
}

func (p *Provider) apiURL() string {
	return strings.TrimSuffix(strings.TrimSpace(cmpOr(p.APIURL, defaultAPIURL)), "/")
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// doJSON performs an API request. Opalstack create/update/delete endpoints
// take and return JSON arrays of objects (matching the official
// opalstack-python client); list/read endpoints return a single array or
// object. out may be nil.
func (p *Provider) doJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.apiURL()+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+p.APIToken)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("opalstack API: %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("opalstack API: %s %s: decoding response: %w", method, path, err)
	}
	return nil
}

// unmarshalFlexible decodes either a JSON array or a single JSON object into a
// slice, tolerating either shape from create endpoints.
func unmarshalFlexible[T any](raw json.RawMessage) ([]T, error) {
	var many []T
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, nil
	}
	var one T
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []T{one}, nil
}

func (p *Provider) listDomains(ctx context.Context) ([]opalDomain, error) {
	var out []opalDomain
	err := p.doJSON(ctx, http.MethodGet, "/domain/list/", nil, &out)
	return out, err
}

func (p *Provider) createDomain(ctx context.Context, name string) (opalDomain, error) {
	var raw json.RawMessage
	err := p.doJSON(ctx, http.MethodPost, "/domain/create/", []map[string]string{{"name": name}}, &raw)
	if err != nil {
		return opalDomain{}, err
	}
	created, err := unmarshalFlexible[opalDomain](raw)
	if err != nil || len(created) == 0 {
		return opalDomain{}, fmt.Errorf("opalstack API: domain/create returned unexpected body: %w", err)
	}
	return created[0], nil
}

func (p *Provider) listRecords(ctx context.Context) ([]opalRecord, error) {
	var out []opalRecord
	err := p.doJSON(ctx, http.MethodGet, "/dnsrecord/list/", nil, &out)
	return out, err
}

func (p *Provider) createRecords(ctx context.Context, recs []recordCreate) ([]opalRecord, error) {
	var raw json.RawMessage
	if err := p.doJSON(ctx, http.MethodPost, "/dnsrecord/create/", recs, &raw); err != nil {
		return nil, err
	}
	created, err := unmarshalFlexible[opalRecord](raw)
	if err != nil {
		return nil, fmt.Errorf("opalstack API: dnsrecord/create returned unexpected body: %w", err)
	}
	return created, nil
}

func (p *Provider) deleteRecords(ctx context.Context, ids []string) error {
	payload := make([]map[string]string, 0, len(ids))
	for _, id := range ids {
		payload = append(payload, map[string]string{"id": id})
	}
	return p.doJSON(ctx, http.MethodPost, "/dnsrecord/delete/", payload, nil)
}

func (p *Provider) readRecord(ctx context.Context, id string) (opalRecord, error) {
	var out opalRecord
	// read endpoints take no trailing slash; the live API 404s with one
	err := p.doJSON(ctx, http.MethodGet, "/dnsrecord/read/"+id, nil, &out)
	return out, err
}

func (p *Provider) readDomain(ctx context.Context, id string) (opalDomain, error) {
	var out opalDomain
	err := p.doJSON(ctx, http.MethodGet, "/domain/read/"+id, nil, &out)
	return out, err
}

// waitReady polls the given read function until it reports ready, the context
// is cancelled, or the timeout elapses. Opalstack applies changes to its
// nameservers asynchronously (state PENDING_* -> READY).
func waitReady(ctx context.Context, timeout time.Duration, read func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		ready, err := read(ctx)
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for opalstack to apply change: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}
