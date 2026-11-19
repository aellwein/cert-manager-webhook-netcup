package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeZone is a domain the fake netcup account owns.
type fakeZone struct {
	id      int
	managed bool // false: the zone's DNS is still on the legacy backend
}

// fakeRecordKey identifies one ACME challenge record.
type fakeRecordKey struct {
	zoneID int
	scope  string
	value  string
}

// fakeNetcup is an in-memory stand-in for the netcup REST API. Challenge
// records persist between calls, so a test can present, clean up and check
// what is left behind, without touching real DNS.
//
// It answers the calls the solver makes and fails the test on anything else.
// Like netcup, it rejects an invalid key with HTTP 400 and authenticationError.
type fakeNetcup struct {
	t      *testing.T
	apiKey string
	server *httptest.Server

	mu      sync.Mutex
	zones   map[string]fakeZone // zone fqdn -> zone
	records map[fakeRecordKey]bool
}

func newFakeNetcup(t *testing.T, apiKey string, zones map[string]fakeZone) *fakeNetcup {
	t.Helper()
	f := &fakeNetcup{t: t, apiKey: apiKey, zones: zones, records: map[fakeRecordKey]bool{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeNetcup) endpoint() string {
	return f.server.URL
}

// hasRecord reports whether a challenge record with the given scope and value
// exists in the zone.
func (f *fakeNetcup) hasRecord(zone, scope, value string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[fakeRecordKey{f.zones[zone].id, scope, value}]
}

// recordCount returns the number of challenge records across all zones.
func (f *fakeNetcup) recordCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}

// zoneByID returns the fqdn of the zone with the given id.
func (f *fakeNetcup) zoneByID(id int) (string, bool) {
	for fqdn, z := range f.zones {
		if z.id == id {
			return fqdn, true
		}
	}
	return "", false
}

func (f *fakeNetcup) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+f.apiKey {
		writeFakeError(w, http.StatusBadRequest, "authenticationError", "invalid API key")
		return
	}

	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/domain":
		f.lookupDomain(w, r.URL.Query().Get("fqdn"))
	case len(segments) >= 4 && segments[0] == "domain" && segments[2] == "acme" && segments[3] == "challenge":
		f.challenges(w, r, segments)
	default:
		f.t.Errorf("fake netcup: unexpected request %s %s", r.Method, r.URL.RequestURI())
		writeFakeError(w, http.StatusNotFound, "resourceDoesNotExist", "unknown route")
	}
}

func (f *fakeNetcup) lookupDomain(w http.ResponseWriter, fqdn string) {
	z, ok := f.zones[fqdn]
	if !ok {
		writeFakeError(w, http.StatusNotFound, "resourceDoesNotExist", fmt.Sprintf("no domain %q", fqdn))
		return
	}
	writeFakeOK(w, []map[string]any{{"id": z.id, "fqdn": fqdn, "isDnsManaged": z.managed}})
}

// challenges handles /domain/{id}/acme/challenge and
// /domain/{id}/acme/challenge/{scope}/{value}.
func (f *fakeNetcup) challenges(w http.ResponseWriter, r *http.Request, segments []string) {
	id, err := strconv.Atoi(segments[1])
	if err != nil {
		writeFakeError(w, http.StatusBadRequest, "validationError", "domain id must be numeric")
		return
	}
	zone, ok := f.zoneByID(id)
	if !ok {
		writeFakeError(w, http.StatusNotFound, "resourceDoesNotExist", "no such domain")
		return
	}

	switch {
	case len(segments) == 4 && r.Method == http.MethodPost:
		var body struct {
			Scope string `json:"scope"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeFakeError(w, http.StatusBadRequest, "validationError", err.Error())
			return
		}
		f.records[fakeRecordKey{id, body.Scope, body.Value}] = true // adding is idempotent
		writeFakeCreated(w, body.Scope, zone, body.Value)
	case len(segments) == 4 && r.Method == http.MethodGet:
		var list []map[string]any
		for key := range f.records {
			if key.zoneID == id {
				list = append(list, map[string]any{"scope": key.scope, "fqdn": challengeName(key.scope, zone), "value": key.value, "status": "pending"})
			}
		}
		writeFakeOK(w, list)
	case len(segments) == 6:
		key := fakeRecordKey{id, segments[4], segments[5]}
		switch r.Method {
		case http.MethodDelete:
			if !f.records[key] {
				writeFakeError(w, http.StatusNotFound, "resourceDoesNotExist", "no such challenge record")
				return
			}
			delete(f.records, key)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			if !f.records[key] {
				writeFakeError(w, http.StatusNotFound, "resourceDoesNotExist", "no such challenge record")
				return
			}
			writeFakeOK(w, []map[string]any{{"scope": key.scope, "fqdn": challengeName(key.scope, zone), "value": key.value, "status": "pending"}})
		default:
			f.t.Errorf("fake netcup: unexpected method %s on a challenge record", r.Method)
			writeFakeError(w, http.StatusMethodNotAllowed, "validationError", "method not allowed")
		}
	default:
		f.t.Errorf("fake netcup: unexpected request %s %s", r.Method, r.URL.RequestURI())
		writeFakeError(w, http.StatusNotFound, "resourceDoesNotExist", "unknown route")
	}
}

// challengeName is the fqdn netcup reports for a scope in a zone: the scope
// prefixed with _acme-challenge, or the prefix alone at the apex.
func challengeName(scope, zone string) string {
	if scope == "@" {
		return "_acme-challenge." + zone + "."
	}
	return "_acme-challenge." + scope + "." + zone + "."
}

func writeFakeOK(w http.ResponseWriter, result any) {
	writeFakeEnvelope(w, http.StatusOK, true, nil, result)
}

func writeFakeCreated(w http.ResponseWriter, scope, zone, value string) {
	result := []map[string]any{{"scope": scope, "fqdn": challengeName(scope, zone), "value": value, "status": "pending"}}
	writeFakeEnvelope(w, http.StatusCreated, true, nil, result)
}

func writeFakeError(w http.ResponseWriter, status int, code, message string) {
	errs := []map[string]string{{"code": code, "message": message}}
	writeFakeEnvelope(w, status, false, errs, nil)
}

func writeFakeEnvelope(w http.ResponseWriter, status int, success bool, errs []map[string]string, result any) {
	if errs == nil {
		errs = []map[string]string{}
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": success, "errors": errs, "result": result})
}
