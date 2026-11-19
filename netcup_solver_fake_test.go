package main

import (
	"strings"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// These tests drive the solver through Present and CleanUp, as cert-manager
// does, against the in-memory fake from netcup_fake_test.go. They need no
// network and no credentials, so they run in every `go test`.

const (
	fakeSecretName = "netcup-fake-secret"
	fakeZoneName   = "example.com"
	fakeZoneID     = 1047093
)

// fakeAccount returns a fake netcup account with one REST-managed zone.
func fakeAccount(t *testing.T, apiKey string) *fakeNetcup {
	t.Helper()
	return newFakeNetcup(t, apiKey, map[string]fakeZone{
		fakeZoneName: {id: fakeZoneID, managed: true},
	})
}

// fakeSolverFor returns a solver whose cluster holds a secret with the given
// API key and whose REST calls go to the fake.
func fakeSolverFor(t *testing.T, f *fakeNetcup, secretKey string) *netcupDNSProviderSolver {
	t.Helper()
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: fakeSecretName, Namespace: "default"},
		Data:       map[string][]byte{"api-key": []byte(secretKey)},
	}
	return &netcupDNSProviderSolver{client: fake.NewClientset(sec), restEndpoint: f.endpoint()}
}

// fakeChallenge builds the request cert-manager sends for a dns-01 challenge
// on resolvedFqdn, which must lie in the given zone.
func fakeChallenge(resolvedFqdn, zone, key string) *v1alpha1.ChallengeRequest {
	return &v1alpha1.ChallengeRequest{
		Action:            v1alpha1.ChallengeActionPresent,
		Type:              "dns-01",
		DNSName:           zone,
		Key:               key,
		ResourceNamespace: "default",
		ResolvedFQDN:      resolvedFqdn,
		ResolvedZone:      zone + ".",
		Config:            &extapi.JSON{Raw: []byte(`{"secretRef":"` + fakeSecretName + `"}`)},
	}
}

func TestFakeSolverPresentAndCleanUpLifecycle(t *testing.T) {
	const apiKey = "fakeRestApiKeyForOfflineTests0000000000000000000000000"
	f := fakeAccount(t, apiKey)
	solver := fakeSolverFor(t, f, apiKey)
	ch := fakeChallenge("_acme-challenge.host.example.com.", fakeZoneName, testKey)

	if err := solver.Present(ch); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !f.hasRecord(fakeZoneName, "host", testKey) {
		t.Fatal("Present did not create the record under the host scope")
	}

	// Present is called again on retry and must not duplicate the record.
	if err := solver.Present(ch); err != nil {
		t.Fatalf("repeated Present: %v", err)
	}
	if n := f.recordCount(); n != 1 {
		t.Errorf("record count after repeated Present = %d, want 1", n)
	}

	if err := solver.CleanUp(ch); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if f.hasRecord(fakeZoneName, "host", testKey) {
		t.Error("CleanUp left the record behind")
	}

	// A record that is already gone is not an error.
	if err := solver.CleanUp(ch); err != nil {
		t.Fatalf("CleanUp on an already-removed record: %v", err)
	}
}

func TestFakeSolverRecordLandsUnderTheChallengeScope(t *testing.T) {
	const apiKey = "fakeRestApiKeyForOfflineTests0000000000000000000000000"
	tests := []struct {
		name      string
		resolved  string
		wantScope string
	}{
		{"subdomain", "_acme-challenge.host.example.com.", "host"},
		{"zone apex", "_acme-challenge.example.com.", "@"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fakeAccount(t, apiKey)
			solver := fakeSolverFor(t, f, apiKey)
			if err := solver.Present(fakeChallenge(tt.resolved, fakeZoneName, testKey)); err != nil {
				t.Fatalf("Present: %v", err)
			}
			if !f.hasRecord(fakeZoneName, tt.wantScope, testKey) {
				t.Errorf("no record with scope %q after presenting %s", tt.wantScope, tt.resolved)
			}
		})
	}
}

func TestFakeSolverRejectsAWrongAPIKey(t *testing.T) {
	f := fakeAccount(t, "fakeRestApiKeyForOfflineTests0000000000000000000000000")
	solver := fakeSolverFor(t, f, "wrongKeyWrongKeyWrongKeyWrongKeyWrongKeyWrongKey1234")

	err := solver.Present(fakeChallenge("_acme-challenge.host.example.com.", fakeZoneName, testKey))
	if err == nil {
		t.Fatal("expected an error for a rejected key")
	}
	for _, want := range []string{"netcup REST API", "the API key was rejected"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
	if f.recordCount() != 0 {
		t.Error("a rejected key must not create a record")
	}
}

func TestFakeSolverRefusesAZoneOnTheLegacyBackend(t *testing.T) {
	const apiKey = "fakeRestApiKeyForOfflineTests0000000000000000000000000"
	f := newFakeNetcup(t, apiKey, map[string]fakeZone{
		fakeZoneName: {id: fakeZoneID, managed: false},
	})
	solver := fakeSolverFor(t, f, apiKey)

	err := solver.Present(fakeChallenge("_acme-challenge.host.example.com.", fakeZoneName, testKey))
	if err == nil {
		t.Fatal("expected an error for a zone not managed through the REST API")
	}
	if !strings.Contains(err.Error(), "legacy") {
		t.Errorf("error %q should point to the legacy API", err)
	}
	if f.recordCount() != 0 {
		t.Error("an unmanaged zone must not create a record")
	}
}

func TestFakeSolverNamesTheMissingZone(t *testing.T) {
	const apiKey = "fakeRestApiKeyForOfflineTests0000000000000000000000000"
	f := fakeAccount(t, apiKey)
	solver := fakeSolverFor(t, f, apiKey)

	err := solver.Present(fakeChallenge("_acme-challenge.host.other.org.", "other.org", testKey))
	if err == nil {
		t.Fatal("expected an error for a zone that is not in the account")
	}
	if !strings.Contains(err.Error(), "unable to find a netcup domain") {
		t.Errorf("error %q should say that no netcup domain was found", err)
	}
}
