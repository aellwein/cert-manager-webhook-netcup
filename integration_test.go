package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Integration tests run against the live netcup API and are skipped unless
// both NETCUP_API_KEY and NETCUP_TEST_DOMAIN are set:
//
//	NETCUP_API_KEY=... NETCUP_TEST_DOMAIN=example.com go test -run Integration -v
//
// They create and remove TXT records under
// _acme-challenge.cert-manager-itest.<domain> and touch nothing else.
const integrationHost = "cert-manager-itest"

func integrationTarget(t *testing.T) (*netcupClientConfig, string) {
	t.Helper()
	apiKey := os.Getenv("NETCUP_API_KEY")
	domain := os.Getenv("NETCUP_TEST_DOMAIN")
	if apiKey == "" || domain == "" {
		t.Skip("set NETCUP_API_KEY and NETCUP_TEST_DOMAIN to run integration tests")
	}
	cfg := &netcupClientConfig{apiKey: apiKey, useRestApi: true}
	// cert-manager presents a resolved FQDN with a trailing dot.
	fqdn := "_acme-challenge." + integrationHost + "." + strings.TrimSuffix(domain, ".") + "."
	return cfg, fqdn
}

// challengeKey returns a value shaped like the one cert-manager presents:
// base64url of a SHA-256 digest, which is 43 characters.
func challengeKey(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// The sequence cert-manager drives: present, present again on retry, clean up,
// and clean up again when the challenge is retried after validation.
func TestIntegrationRestChallengeLifecycle(t *testing.T) {
	cfg, fqdn := integrationTarget(t)
	key := challengeKey(t)

	t.Cleanup(func() {
		if err := addOrDeleteRecord(cfg, fqdn, key, true); err != nil {
			t.Errorf("cleanup failed, record may remain: %v", err)
		}
	})

	if err := addOrDeleteRecord(cfg, fqdn, key, false); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := addOrDeleteRecord(cfg, fqdn, key, false); err != nil {
		t.Fatalf("Present is called repeatedly and must be idempotent: %v", err)
	}
	if err := addOrDeleteRecord(cfg, fqdn, key, true); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if err := addOrDeleteRecord(cfg, fqdn, key, true); err != nil {
		t.Fatalf("CleanUp on an already-removed record must succeed: %v", err)
	}
}

// A legacy key used alone selects the REST API and is rejected. The error has
// to name the API and explain the key length, since nothing else will.
func TestIntegrationRestRejectsALegacyKey(t *testing.T) {
	_, fqdn := integrationTarget(t)
	cfg := &netcupClientConfig{apiKey: strings.Repeat("x", 50), useRestApi: true}

	err := addOrDeleteRecord(cfg, fqdn, challengeKey(t), false)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"netcup REST API", "50 characters"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Happy flow through the solver itself, with a fake Kubernetes clientset
// standing in for the cluster. This covers what the tests above skip: the
// secret lookup, the credential dispatch, and the Present/CleanUp methods
// cert-manager actually calls.
//
// That the record lands under the right name is checked by the unit tests,
// which assert the scope on the wire, and end to end by
// TestIntegrationChallengeBecomesResolvable.
// ---------------------------------------------------------------------------

const integrationSecretName = "netcup-itest-secret"

func integrationSolver(t *testing.T) (*netcupDNSProviderSolver, string) {
	t.Helper()
	apiKey := os.Getenv("NETCUP_API_KEY")
	domain := os.Getenv("NETCUP_TEST_DOMAIN")
	if apiKey == "" || domain == "" {
		t.Skip("set NETCUP_API_KEY and NETCUP_TEST_DOMAIN to run integration tests")
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: integrationSecretName, Namespace: "default"},
		// Only an api-key, so the dispatch has to select the REST API.
		Data: map[string][]byte{"api-key": []byte(apiKey)},
	}
	return &netcupDNSProviderSolver{client: fake.NewClientset(sec)}, strings.TrimSuffix(domain, ".")
}

func challengeRequest(t *testing.T, domain string, key string) *v1alpha1.ChallengeRequest {
	t.Helper()
	return &v1alpha1.ChallengeRequest{
		Action:            v1alpha1.ChallengeActionPresent,
		Type:              "dns-01",
		DNSName:           domain,
		Key:               key,
		ResourceNamespace: "default",
		ResolvedFQDN:      "_acme-challenge." + integrationHost + "." + domain + ".",
		ResolvedZone:      domain + ".",
		Config:            &extapi.JSON{Raw: []byte(`{"secretRef":"` + integrationSecretName + `"}`)},
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestIntegrationSolverPresentAndCleanUp(t *testing.T) {
	solver, domain := integrationSolver(t)
	ch := challengeRequest(t, domain, challengeKey(t))

	t.Cleanup(func() {
		if err := solver.CleanUp(ch); err != nil {
			t.Errorf("cleanup failed, record may remain: %v", err)
		}
	})

	if err := solver.Present(ch); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := solver.Present(ch); err != nil {
		t.Fatalf("Present is called repeatedly and must be idempotent: %v", err)
	}

	if err := solver.CleanUp(ch); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if err := solver.CleanUp(ch); err != nil {
		t.Fatalf("CleanUp on an already-removed record must succeed: %v", err)
	}
}

// authoritativeResolver resolves against the given nameserver directly, so a
// cached answer from the system resolver cannot make the test pass.
func authoritativeResolver(nameserver string) *net.Resolver {
	addr := net.JoinHostPort(strings.TrimSuffix(nameserver, "."), "53")
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

// Presenting a challenge is only useful if the ACME server can read it.
// netcup reports the record as "deployed" within a second or two, but it does
// not become resolvable for about a minute, so this polls rather than trusting
// the status.
//
// Two challenges are presented at the same name, as a certificate covering
// both example.com and *.example.com produces. Both values have to appear:
// the ACME server reads whichever one it is currently validating, and the
// legacy API cannot express this at all.
func TestIntegrationChallengeBecomesResolvable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: waits for DNS propagation")
	}
	solver, domain := integrationSolver(t)
	challenges := []*v1alpha1.ChallengeRequest{
		challengeRequest(t, domain, challengeKey(t)),
		challengeRequest(t, domain, challengeKey(t)),
	}
	name := "_acme-challenge." + integrationHost + "." + domain

	t.Cleanup(func() {
		for _, ch := range challenges {
			if err := solver.CleanUp(ch); err != nil {
				t.Errorf("cleanup failed, record may remain: %v", err)
			}
		}
	})

	for i, ch := range challenges {
		if err := solver.Present(ch); err != nil {
			t.Fatalf("Present %d of %d: %v", i+1, len(challenges), err)
		}
	}

	nameservers, err := net.LookupNS(domain)
	if err != nil || len(nameservers) == 0 {
		t.Fatalf("looking up nameservers for %s: %v", domain, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	start := time.Now()

	// Every authoritative nameserver has to serve both: publication is
	// staggered, and the ACME server may ask any of them.
	for _, ns := range nameservers {
		resolver := authoritativeResolver(ns.Host)
		for {
			values, lookupErr := resolver.LookupTXT(ctx, name)
			if lookupErr == nil && contains(values, challenges[0].Key) && contains(values, challenges[1].Key) {
				t.Logf("%s serves both challenges after %s", ns.Host, time.Since(start).Round(time.Second))
				break
			}
			select {
			case <-ctx.Done():
				t.Fatalf("%s did not serve both challenges for %s within %s: have %v, want %q and %q (last error: %v)",
					ns.Host, name, time.Since(start).Round(time.Second),
					values, challenges[0].Key, challenges[1].Key, lookupErr)
			case <-time.After(10 * time.Second):
			}
		}
	}
	t.Logf("both challenges resolvable on all %d nameservers after %s",
		len(nameservers), time.Since(start).Round(time.Second))
}
