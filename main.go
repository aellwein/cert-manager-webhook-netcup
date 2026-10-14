package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	netcuprest "github.com/aellwein/netcup-dns-api/pkg/rest/v1"
	netcup "github.com/aellwein/netcup-dns-api/pkg/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

var (
	GroupName        = os.Getenv("GROUP_NAME")
	version   string = "0.0.0-dev"
)

func main() {
	klog.Infof("starting cert-manager-webhook-netcup (version %s)", version)
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	klog.Infof("current capabilities: %s", cap.GetProc())
	caps := cap.NewSet()
	required := []cap.Value{cap.NET_BIND_SERVICE}
	if err := errors.Join(
		caps.SetFlag(cap.Effective, true, required...),
		caps.SetFlag(cap.Permitted, true, required...),
		caps.SetProc(),
	); err != nil {
		klog.Fatalf("activating capabilities: %s: %v", caps, err)
	}
	klog.Infof("activated capabilities: %s", cap.GetProc())
	cmd.RunWebhookServer(GroupName,
		&netcupDNSProviderSolver{},
	)
}

// These are the things required to interact with Netcup API, should be located
// in secret, referenced in config by it's name
type netcupClientConfig struct {
	customerNumber int
	apiKey         string
	apiPassword    string
	// useRestApi selects the REST API at api.netcup.com over the legacy CCP
	// API. See netcupConfigFromSecret for how it is decided.
	useRestApi bool
	// restEndpoint overrides the REST API base URL. Only set in tests.
	restEndpoint string
}

// apiName names the netcup API this configuration selected, for log messages.
func (c *netcupClientConfig) apiName() string {
	if c.useRestApi {
		return "netcup REST API"
	}
	return "legacy netcup CCP API"
}

// netcupConfigFromSecret decides which netcup API to use from the keys the
// secret carries. The legacy CCP API needs a customer number and an API
// password besides the key; the REST API needs the key alone. A secret
// carrying only 'api-key' therefore selects the REST API, and one carrying all
// three keeps using the legacy API, so existing secrets are unaffected.
//
// Half a set of legacy credentials is rejected rather than quietly treated as
// a REST configuration, which would authenticate against the wrong API and
// fail with an unhelpful message from netcup.
func netcupConfigFromSecret(secretData map[string][]byte) (*netcupClientConfig, error) {
	apiKey, err := stringFromSecretData(&secretData, "api-key")
	if err != nil {
		return nil, fmt.Errorf("unable to get 'api-key' from secret: %v", err)
	}
	cfg := &netcupClientConfig{apiKey: apiKey}

	customerNumber, hasCustomerNumber := secretData["customer-number"]
	apiPassword, hasApiPassword := secretData["api-password"]

	switch {
	case !hasCustomerNumber && !hasApiPassword:
		cfg.useRestApi = true
		return cfg, nil
	case !hasApiPassword:
		return nil, fmt.Errorf(
			"secret has 'customer-number' but no 'api-password': the legacy CCP API needs both, "+
				"while the REST API needs neither. %s", apiKeyHint(apiKey))
	case !hasCustomerNumber:
		return nil, fmt.Errorf(
			"secret has 'api-password' but no 'customer-number': the legacy CCP API needs both, "+
				"while the REST API needs neither. %s", apiKeyHint(apiKey))
	}

	cfg.customerNumber, err = strconv.Atoi(string(customerNumber))
	if err != nil {
		return nil, fmt.Errorf("expected 'customer-number' to be a numeric int value, got '%s'", customerNumber)
	}
	cfg.apiPassword = string(apiPassword)
	return cfg, nil
}

// apiKeyHint guesses which kind of key the secret holds from its length, for
// use in error messages only. netcup's REST API keys are 64 characters and the
// legacy CCP keys 50, but this is undocumented, so it never decides which API
// is used.
func apiKeyHint(apiKey string) string {
	switch len(apiKey) {
	case 64:
		return "The key is 64 characters, which looks like a REST API key: remove 'customer-number' and 'api-password' from the secret to use the REST API."
	case 50:
		return "The key is 50 characters, which looks like a legacy CCP API key: add the missing key to the secret."
	default:
		return "Add the missing key to use the legacy CCP API, or remove both to use the REST API."
	}
}

type netcupDNSProviderSolver struct {
	// client is the interface rather than *kubernetes.Clientset so that the
	// solver can be driven with a fake clientset in tests.
	client kubernetes.Interface
}

type netcupDNSProviderConfig struct {
	// name of the secret which contains Netcup credentials
	SecretRef string `json:"secretRef"`
	// optional namespace for the secret
	SecretNamespace string `json:"secretNamespace"`
}

func (n *netcupDNSProviderSolver) Name() string {
	return "netcup"
}

func (n *netcupDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := n.getConfig(ch)
	if err != nil {
		return err
	}
	if err := addOrDeleteRecord(cfg, ch.ResolvedFQDN, ch.Key, false); err != nil {
		return err
	}
	klog.Infof("successfully presented challenge for domain '%s' via the %s", ch.DNSName, cfg.apiName())
	return nil
}

func (n *netcupDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := n.getConfig(ch)
	if err != nil {
		return err
	}
	if err := addOrDeleteRecord(cfg, ch.ResolvedFQDN, ch.Key, true); err != nil {
		return err
	}
	klog.Infof("successfully cleaned up challenge for domain '%s' via the %s", ch.DNSName, cfg.apiName())
	return nil
}

func (n *netcupDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	n.client = cl
	return nil
}

func (n *netcupDNSProviderSolver) getConfig(ch *v1alpha1.ChallengeRequest) (*netcupClientConfig, error) {
	var secretNs string
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	if cfg.SecretNamespace != "" {
		secretNs = cfg.SecretNamespace
	} else {
		secretNs = ch.ResourceNamespace
	}

	sec, err := n.client.CoreV1().Secrets(secretNs).Get(context.TODO(), cfg.SecretRef, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}

	netcupCfg, err := netcupConfigFromSecret(sec.Data)
	if err != nil {
		return nil, fmt.Errorf("secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}
	return netcupCfg, nil
}

// addOrDeleteRecord presents or removes a challenge record using whichever
// netcup API the secret selected.
func addOrDeleteRecord(cfg *netcupClientConfig, resolvedFqdn string, key string, delete bool) error {
	var err error
	if cfg.useRestApi {
		err = addOrDeleteChallengeRecord(cfg, resolvedFqdn, key, delete)
	} else {
		err = addOrDeleteTxtRecord(cfg, resolvedFqdn, key, delete)
	}
	if err != nil {
		// Nothing is logged on the failure path, so the error has to say
		// which API it was talking to.
		return fmt.Errorf("%s: %w", cfg.apiName(), err)
	}
	return nil
}

// addOrDeleteChallengeRecord presents or removes a challenge through the
// dedicated ACME endpoints of the netcup REST API.
func addOrDeleteChallengeRecord(cfg *netcupClientConfig, resolvedFqdn string, key string, delete bool) error {
	// The ACME endpoints of the REST API can only manage _acme-challenge
	// records. A name without that prefix usually means the challenge was
	// CNAME-delegated to a target that does not carry it, so say that rather
	// than let the zone lookup fail with something unrelated.
	if !strings.HasPrefix(resolvedFqdn, netcuprest.AcmeChallengePrefix) {
		return fmt.Errorf(
			"'%s' is not an %s record, which is all the ACME endpoints of the netcup REST API can manage. "+
				"This usually means the challenge was CNAME-delegated (cnameStrategy: Follow) to a target "+
				"without the '%s' prefix. Point the CNAME at an %s name, or use legacy credentials for this domain",
			resolvedFqdn, netcuprest.AcmeChallengePrefix, netcuprest.AcmeChallengePrefix, netcuprest.AcmeChallengePrefix)
	}

	client := netcuprest.NewClient(cfg.apiKey, &netcuprest.ClientOptions{Endpoint: cfg.restEndpoint})
	ctx := context.TODO()

	domain, err := client.ResolveDomain(ctx, resolvedFqdn)
	if err != nil {
		if netcuprest.IsAuthError(err) {
			return fmt.Errorf("the API key was rejected: %v. %s", err, apiKeyHint(cfg.apiKey))
		}
		return fmt.Errorf("unable to find a netcup domain for '%s': %v", resolvedFqdn, err)
	}
	if !domain.IsDnsManaged {
		return fmt.Errorf(
			"the DNS of domain '%s' is not managed through it. "+
				"Add 'customer-number' and 'api-password' to the secret to use the legacy CCP API for this domain",
			domain.Fqdn)
	}

	scope, err := netcuprest.AcmeScope(resolvedFqdn, domain.Fqdn)
	if err != nil {
		return fmt.Errorf("unable to derive the challenge scope for '%s': %v", resolvedFqdn, err)
	}

	if delete {
		// A record that is already gone is not an error for us.
		if err := client.DeleteAcmeChallenge(ctx, domain.Id, scope, key); err != nil && !netcuprest.IsNotFound(err) {
			return fmt.Errorf("failed to remove the challenge record for '%s': %v", resolvedFqdn, err)
		}
		return nil
	}
	// Adding is idempotent, so a repeated Present for the same challenge is fine.
	if _, err := client.AddAcmeChallenge(ctx, domain.Id, scope, key); err != nil {
		return fmt.Errorf("failed to set the challenge record for '%s': %v", resolvedFqdn, err)
	}
	return nil
}

func addOrDeleteTxtRecord(cfg *netcupClientConfig, resolvedFqdn string, key string, delete bool) error {
	netcupClient := netcup.NewNetcupDnsClient(cfg.customerNumber, cfg.apiKey, cfg.apiPassword)
	sess, err := netcupClient.Login()
	if err != nil {
		return fmt.Errorf("unable to login to netcup API: %v", err)
	}
	defer sess.Logout()

	rePattern := regexp.MustCompile(`^(.+)\.(([^\.]+)\.([^\.]+))\.$`)
	match := rePattern.FindStringSubmatch(resolvedFqdn)
	if match == nil {
		return fmt.Errorf("unable to parse host/domain out of resolved FQDN ('%s')", resolvedFqdn)
	}
	host := match[1]
	domain := match[2]

	recs, err := sess.InfoDnsRecords(domain)
	if err != nil {
		if sess.LastResponse != nil &&
			sess.LastResponse.Status == string(netcup.StatusError) &&
			sess.LastResponse.StatusCode == 5029 {
			// See https://github.com/aellwein/cert-manager-webhook-netcup/issues/41
			// Netcup API returns an error here, but for us it is actually a warning in case no DNS records are found for the domain.
			// The resulting records will be an empty DnsRecord array, so we just proceed here.
		} else {
			return fmt.Errorf("unable to get DNS records for domain '%s': %v", resolvedFqdn, err)
		}
	}
	var foundRec *netcup.DnsRecord
	for _, rec := range *recs {
		// record already exists?
		if host == rec.Hostname && rec.Type == "TXT" {
			foundRec = &rec
			break
		}
	}
	if foundRec != nil {
		if !delete {
			if foundRec.Destination == key {
				// record already contains the challenge, nothing to do
				return nil
			}
			foundRec.Destination = key
			foundRec.DeleteRecord = false
		} else {
			foundRec.DeleteRecord = true
		}
	} else {
		if delete {
			// record is already gone -> nothing to do
			return nil
		}
		foundRec = &netcup.DnsRecord{
			Id:           "",
			Hostname:     host,
			Type:         "TXT",
			Priority:     "",
			Destination:  key,
			DeleteRecord: false,
			State:        "yes",
		}
	}
	if _, err := sess.UpdateDnsRecords(domain, &[]netcup.DnsRecord{*foundRec}); err != nil {
		return fmt.Errorf("failed to set TXT record for domain '%s': %v, record to set: %v", resolvedFqdn, err, foundRec)
	}
	return nil
}

func stringFromSecretData(secretData *map[string][]byte, key string) (string, error) {
	data, ok := (*secretData)[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret data", key)
	}
	return string(data), nil
}

func loadConfig(cfgJSON *extapi.JSON) (netcupDNSProviderConfig, error) {
	cfg := netcupDNSProviderConfig{}

	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}
