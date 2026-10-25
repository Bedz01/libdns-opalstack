package opalstack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// mockAPI is an in-memory Opalstack API good enough for the provider:
// domain list/create/read, dnsrecord list/create/read/delete. Newly created
// objects report ready=false until they have been read once, exercising the
// wait-for-READY polling.
type mockAPI struct {
	mu       sync.Mutex
	domains  map[string]*opalDomain
	records  map[string]*opalRecord
	nextID   int
	authSeen string
}

func newMockAPI() *mockAPI {
	m := &mockAPI{domains: map[string]*opalDomain{}, records: map[string]*opalRecord{}}
	m.addDomain("example.com", true)
	m.addDomain("www.example.com", true)
	m.addDomain("unrelated.example", true)
	return m
}

func (m *mockAPI) addDomain(name string, ready bool) *opalDomain {
	m.nextID++
	d := &opalDomain{ID: fmt.Sprintf("dom-%d", m.nextID), Name: name, Ready: ready, State: "READY"}
	m.domains[d.ID] = d
	return d
}

func (m *mockAPI) addRecord(domID, typ, content string, prio, ttl int, ready bool) *opalRecord {
	m.nextID++
	r := &opalRecord{ID: fmt.Sprintf("rec-%d", m.nextID), Domain: domID, Type: typ, Content: content, Priority: prio, TTL: ttl, Ready: ready, State: "READY"}
	m.records[r.ID] = r
	return r
}

func (m *mockAPI) handler(t *testing.T) http.Handler {
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.authSeen = r.Header.Get("Authorization")

		switch {
		case r.URL.Path == "/domain/list/":
			out := []opalDomain{}
			for _, d := range m.domains {
				out = append(out, *d)
			}
			writeJSON(w, out)
		case r.URL.Path == "/domain/create/":
			var in []map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			out := []opalDomain{}
			for _, item := range in {
				d := m.addDomain(item["name"], false) // pending until first read
				out = append(out, *d)
			}
			writeJSON(w, out)
		case strings.HasPrefix(r.URL.Path, "/domain/read/"):
			id := strings.TrimPrefix(r.URL.Path, "/domain/read/") // no trailing slash, as live
			d, ok := m.domains[id]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			resp := *d
			d.Ready = true // becomes ready after first poll
			writeJSON(w, resp)
		case r.URL.Path == "/dnsrecord/list/":
			out := []opalRecord{}
			for _, rec := range m.records {
				out = append(out, *rec)
			}
			writeJSON(w, out)
		case r.URL.Path == "/dnsrecord/create/":
			var in []recordCreate
			json.NewDecoder(r.Body).Decode(&in)
			out := []opalRecord{}
			for _, c := range in {
				if c.TTL != 0 && c.TTL < 300 {
					http.Error(w, "ttl below minimum", 400)
					return
				}
				if _, ok := m.domains[c.Domain]; !ok {
					http.Error(w, "unknown domain "+c.Domain, 400)
					return
				}
				rec := m.addRecord(c.Domain, c.Type, c.Content, c.Priority, c.TTL, false)
				out = append(out, *rec)
			}
			writeJSON(w, out)
		case strings.HasPrefix(r.URL.Path, "/dnsrecord/read/"):
			id := strings.TrimPrefix(r.URL.Path, "/dnsrecord/read/")
			rec, ok := m.records[id]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			resp := *rec
			rec.Ready = true
			writeJSON(w, resp)
		case r.URL.Path == "/dnsrecord/delete/":
			var in []map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			for _, item := range in {
				delete(m.records, item["id"])
			}
			writeJSON(w, map[string]any{})
		default:
			t.Errorf("mock API got unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 500)
		}
	})
}

func newTestProvider(t *testing.T) (*Provider, *mockAPI) {
	m := newMockAPI()
	srv := httptest.NewServer(m.handler(t))
	t.Cleanup(srv.Close)
	return &Provider{APIToken: "test-token", APIURL: srv.URL, PropagationTimeout: 5 * time.Second}, m
}

func findDomain(m *mockAPI, name string) *opalDomain {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.domains {
		if d.Name == name {
			return d
		}
	}
	return nil
}

func TestAppendTXTCreatesDomainAndRecord(t *testing.T) {
	p, m := newTestProvider(t)
	got, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", TTL: 0, Text: "challenge-token-value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 record back, got %d", len(got))
	}
	txt, ok := got[0].(libdns.TXT)
	if !ok {
		t.Fatalf("want libdns.TXT back, got %T", got[0])
	}
	if txt.Name != "_acme-challenge" || txt.Text != "challenge-token-value" {
		t.Errorf("round-trip mismatch: %+v", txt)
	}
	dom := findDomain(m, "_acme-challenge.example.com")
	if dom == nil {
		t.Fatal("expected _acme-challenge.example.com Domain to be created")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var rec *opalRecord
	for _, r := range m.records {
		if r.Domain == dom.ID {
			rec = r
		}
	}
	if rec == nil || rec.Type != "TXT" || rec.Content != "challenge-token-value" {
		t.Fatalf("record not created correctly: %+v", rec)
	}
	if rec.TTL < 300 {
		t.Errorf("TTL %d below Opalstack minimum", rec.TTL)
	}
	if m.authSeen != "Token test-token" {
		t.Errorf("wrong auth header: %q", m.authSeen)
	}
}

func TestAppendReusesExistingDomain(t *testing.T) {
	p, m := newTestProvider(t)
	before := len(m.domains)
	_, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "www", Text: "hello"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.domains) != before {
		t.Errorf("should have reused www.example.com Domain, but domain count went %d -> %d", before, len(m.domains))
	}
}

func TestGetRecordsScopedToZone(t *testing.T) {
	p, m := newTestProvider(t)
	apex := findDomain(m, "example.com")
	www := findDomain(m, "www.example.com")
	other := findDomain(m, "unrelated.example")
	m.mu.Lock()
	m.addRecord(apex.ID, "MX", "mx1.us.opalstack.com", 10, 3600, true)
	m.addRecord(www.ID, "A", "192.0.2.10", 0, 3600, true)
	m.addRecord(other.ID, "A", "9.9.9.9", 0, 3600, true)
	m.mu.Unlock()

	got, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 records (unrelated.example excluded), got %d: %+v", len(got), got)
	}
	names := map[string]string{}
	for _, r := range got {
		rr := r.RR()
		names[rr.Name] = rr.Data
	}
	if _, ok := names["@"]; !ok {
		t.Errorf("apex MX should have relative name '@', got: %v", names)
	}
	if names["www"] != "192.0.2.10" {
		t.Errorf("www A record wrong: %v", names)
	}
	// MX data should include the priority.
	if !strings.HasPrefix(names["@"], "10 ") {
		t.Errorf("MX data should carry priority prefix, got %q", names["@"])
	}
}

func TestDeleteRecordsWildcardFields(t *testing.T) {
	p, m := newTestProvider(t)
	apex := findDomain(m, "example.com")
	m.mu.Lock()
	acme := m.addDomain("_acme-challenge.example.com", true)
	m.addRecord(acme.ID, "TXT", "stale-challenge", 0, 300, true)
	m.addRecord(apex.ID, "TXT", "v=spf1 include:spf.opalstack.com ~all", 0, 3600, true)
	m.mu.Unlock()

	// Type+name only — TTL and Data left empty as wildcards.
	deleted, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.RR{Name: "_acme-challenge", Type: "TXT"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 {
		t.Fatalf("want 1 deleted, got %d", len(deleted))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.records {
		if r.Content == "stale-challenge" {
			t.Error("stale challenge record should have been deleted")
		}
	}
	if len(m.records) != 1 {
		t.Errorf("SPF record on apex must survive, records left: %d", len(m.records))
	}
}

func TestSetRecordsReplacesRRset(t *testing.T) {
	p, m := newTestProvider(t)
	m.mu.Lock()
	acme := m.addDomain("_acme-challenge.example.com", true)
	m.addRecord(acme.ID, "TXT", "old-1", 0, 300, true)
	m.addRecord(acme.ID, "TXT", "old-2", 0, 300, true)
	m.addRecord(acme.ID, "A", "1.2.3.4", 0, 300, true) // different type: untouched
	m.mu.Unlock()

	got, err := p.SetRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "new-only"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 record back, got %d", len(got))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var txts, as int
	for _, r := range m.records {
		if r.Domain != acme.ID {
			continue
		}
		switch r.Type {
		case "TXT":
			txts++
			if r.Content != "new-only" {
				t.Errorf("surviving TXT should be new-only, got %q", r.Content)
			}
		case "A":
			as++
		}
	}
	if txts != 1 || as != 1 {
		t.Errorf("want exactly 1 TXT and 1 A after SetRecords, got %d TXT, %d A", txts, as)
	}
}

func TestZoneWithoutTrailingDot(t *testing.T) {
	p, _ := newTestProvider(t)
	_, err := p.AppendRecords(context.Background(), "example.com", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "x"},
	})
	if err != nil {
		t.Fatalf("zone without trailing dot must work: %v", err)
	}
}
