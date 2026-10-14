package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func secret(pairs ...string) map[string][]byte {
	data := make(map[string][]byte, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		data[pairs[i]] = []byte(pairs[i+1])
	}
	return data
}

const (
	restKey   = "odeFPdrsdv0DkYkJO27cpRGWydB05G9xxXJa9QZwv2QodeFPdrsdv0DkYkJO27c" // 64 chars
	legacyKey = "someLegacyCcpApiKeyOf50CharactersForThisTestCase00"              // 50 chars
)

// A secret holding only an API key selects the REST API: there is nothing for
// the legacy API to authenticate with.
func TestConfigFromSecretSelectsRestWhenOnlyApiKeyIsPresent(t *testing.T) {
	cfg, err := netcupConfigFromSecret(secret("api-key", restKey))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.useRestApi {
		t.Error("expected the REST API to be selected")
	}
	if cfg.apiKey != restKey {
		t.Errorf("apiKey = %q, want %q", cfg.apiKey, restKey)
	}
}

// Existing installations carry all three keys and must keep using the legacy
// API exactly as before.
func TestConfigFromSecretSelectsLegacyWhenAllCredentialsArePresent(t *testing.T) {
	cfg, err := netcupConfigFromSecret(secret(
		"customer-number", "123456",
		"api-key", legacyKey,
		"api-password", "somePassword",
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.useRestApi {
		t.Error("expected the legacy API to be selected")
	}
	if cfg.customerNumber != 123456 {
		t.Errorf("customerNumber = %d, want 123456", cfg.customerNumber)
	}
	if cfg.apiPassword != "somePassword" {
		t.Errorf("apiPassword = %q, want %q", cfg.apiPassword, "somePassword")
	}
}

// Half a set of legacy credentials is a mistake, not a request for the REST
// API. Silently ignoring the stray key would authenticate against the wrong
// API and fail with netcup's unhelpful message.
func TestConfigFromSecretRejectsPartialLegacyCredentials(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    map[string][]byte
		wanting string
	}{
		{
			"customer-number without api-password",
			secret("api-key", legacyKey, "customer-number", "123456"),
			"api-password",
		},
		{
			"api-password without customer-number",
			secret("api-key", legacyKey, "api-password", "somePassword"),
			"customer-number",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := netcupConfigFromSecret(tc.data)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wanting) {
				t.Errorf("error %q should name the missing key %q", err, tc.wanting)
			}
		})
	}
}

func TestConfigFromSecretRequiresAnApiKey(t *testing.T) {
	_, err := netcupConfigFromSecret(secret("customer-number", "123456"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "api-key") {
		t.Errorf("error %q should name the missing key", err)
	}
}

func TestConfigFromSecretRejectsNonNumericCustomerNumber(t *testing.T) {
	_, err := netcupConfigFromSecret(secret(
		"customer-number", "not-a-number",
		"api-key", legacyKey,
		"api-password", "somePassword",
	))
	if err == nil {
		t.Fatal("expected an error")
	}
}

const (
	testFqdn   = "_acme-challenge.host.example.com."
	testKey    = "odeFPdrsdv0DkYkJO27cpRGWydB05G9xxXJa9QZwv2Q"
	testDomain = 1047093
)

// netcupTestServer answers the REST API calls a challenge makes. Requests it
// does not recognise fail the test, so an unexpected call is visible.
func netcupTestServer(t *testing.T, dnsManaged bool, record func(method, body string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		// The walk skips _acme-challenge and tries the longest suffix first.
		case r.URL.RequestURI() == "/domain?fqdn=host.example.com":
			w.WriteHeader(404)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":"resourceDoesNotExist","message":"no"}],"result":null}`)
		case r.URL.RequestURI() == "/domain?fqdn=example.com":
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":[{"id":%d,"fqdn":"example.com","isDnsManaged":%t}]}`,
				testDomain, dnsManaged)
		case r.Method == "POST" && r.URL.Path == fmt.Sprintf("/domain/%d/acme/challenge", testDomain):
			body, _ := io.ReadAll(r.Body)
			record("POST", string(body))
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"success":true,"errors":[],"result":[{"scope":"host","fqdn":"_acme-challenge.host.example.com","value":%q,"status":"pending"}]}`, testKey)
		case r.Method == "DELETE" && r.URL.Path == fmt.Sprintf("/domain/%d/acme/challenge/host/%s", testDomain, testKey):
			record("DELETE", "")
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
			w.WriteHeader(500)
		}
	}))
}

func restConfig(endpoint string) *netcupClientConfig {
	return &netcupClientConfig{apiKey: restKey, useRestApi: true, restEndpoint: endpoint}
}

func TestRestPresentCreatesTheChallengeRecord(t *testing.T) {
	var calls []string
	var body string
	ts := netcupTestServer(t, true, func(m, b string) {
		calls = append(calls, m)
		body = b
	})
	defer ts.Close()

	if err := addOrDeleteRecord(restConfig(ts.URL), testFqdn, testKey, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 || calls[0] != "POST" {
		t.Errorf("calls = %v, want one POST", calls)
	}
	// The scope travels in the body, so this is the only place a wrong one
	// would show up. netcup accepts any valid scope, so getting it wrong
	// creates a record under a name nothing will ever query.
	var sent struct {
		Scope string `json:"scope"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(body), &sent); err != nil {
		t.Fatalf("decoding request body %q: %v", body, err)
	}
	if sent.Scope != "host" {
		t.Errorf("scope = %q, want %q (from %s in example.com)", sent.Scope, "host", testFqdn)
	}
	if sent.Value != testKey {
		t.Errorf("value = %q, want %q", sent.Value, testKey)
	}
}

func TestRestCleanUpRemovesTheChallengeRecord(t *testing.T) {
	var calls []string
	ts := netcupTestServer(t, true, func(m, _ string) { calls = append(calls, m) })
	defer ts.Close()

	if err := addOrDeleteRecord(restConfig(ts.URL), testFqdn, testKey, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 || calls[0] != "DELETE" {
		t.Errorf("calls = %v, want one DELETE", calls)
	}
}

// A domain still on the legacy DNS backend cannot be managed here. The error
// has to say what to do about it, since nothing validates the secret earlier.
func TestRestRejectsDomainNotManagedViaRest(t *testing.T) {
	ts := netcupTestServer(t, false, func(string, string) {})
	defer ts.Close()

	err := addOrDeleteRecord(restConfig(ts.URL), testFqdn, testKey, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"customer-number", "api-password"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

// A legacy key used alone selects the REST API and is rejected by netcup. The
// error must point at the real cause rather than passing netcup's message
// through unexplained.
func TestRestAuthFailureExplainsTheKeyLength(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":"authenticationError","message":"Authentication token is not valid or has expired."}],"result":null}`)
	}))
	defer ts.Close()

	cfg := &netcupClientConfig{apiKey: legacyKey, useRestApi: true, restEndpoint: ts.URL}
	err := addOrDeleteRecord(cfg, testFqdn, testKey, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "50 characters") {
		t.Errorf("error %q should explain the key length", err)
	}
}

// A failure has to say which API it was talking to. Nothing is logged on the
// failure path, so the error is the only place that carries it.
func TestErrorsNameTheApiThatFailed(t *testing.T) {
	ts := netcupTestServer(t, false, func(string, string) {})
	defer ts.Close()

	err := addOrDeleteRecord(restConfig(ts.URL), testFqdn, testKey, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "netcup REST API") {
		t.Errorf("error %q should name the API", err)
	}
}

// The zone lookup failing is the error a misconfigured secret most often
// produces, and on its own it says nothing about which API was tried.
func TestZoneLookupFailureNamesTheApi(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":"resourceDoesNotExist","message":"no"}],"result":null}`)
	}))
	defer ts.Close()

	err := addOrDeleteRecord(restConfig(ts.URL), testFqdn, testKey, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "netcup REST API") {
		t.Errorf("error %q should name the API", err)
	}
}

// With cnameStrategy: Follow, cert-manager resolves the CNAME chain and hands
// the webhook the target name. If that target is not an _acme-challenge
// record, netcup's ACME endpoints cannot express it. The error has to say so,
// because the user's mental model is "I set up CNAME delegation", not "my FQDN
// lacks a prefix".
func TestRestRejectsANameWithoutTheChallengePrefix(t *testing.T) {
	ts := netcupTestServer(t, true, func(string, string) {})
	defer ts.Close()

	err := addOrDeleteRecord(restConfig(ts.URL), "validation.delegated.de.", testKey, false)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"_acme-challenge", "CNAME", "cnameStrategy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}
