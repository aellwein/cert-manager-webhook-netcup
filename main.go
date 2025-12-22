package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"

	netcup "github.com/aellwein/netcup-dns-api/pkg/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
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
}

type netcupDNSProviderSolver struct {
	client *kubernetes.Clientset
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
	if err := addOrDeleteTxtRecord(cfg, ch.ResolvedFQDN, ch.Key, false); err != nil {
		return err
	}
	klog.Infof("successfully presented challenge for domain '%s'", ch.DNSName)
	return nil
}

func (n *netcupDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := n.getConfig(ch)
	if err != nil {
		return err
	}
	if err := addOrDeleteTxtRecord(cfg, ch.ResolvedFQDN, ch.Key, true); err != nil {
		return err
	}
	klog.Infof("successfully cleaned up challenge for domain '%s'", ch.DNSName)
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

	netcupCfg := &netcupClientConfig{}

	if cfg.SecretNamespace != "" {
		secretNs = cfg.SecretNamespace
	} else {
		secretNs = ch.ResourceNamespace
	}

	sec, err := n.client.CoreV1().Secrets(secretNs).Get(context.TODO(), cfg.SecretRef, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}

	customerNumber, err := stringFromSecretData(&sec.Data, "customer-number")
	if err != nil {
		return nil, fmt.Errorf("unable to get 'customer-number' from secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}
	netcupCfg.customerNumber, err = strconv.Atoi(customerNumber)
	if err != nil {
		return nil, fmt.Errorf("expected 'customer-number' to be a numeric int value, got '%s'", customerNumber)
	}
	netcupCfg.apiKey, err = stringFromSecretData(&sec.Data, "api-key")
	if err != nil {
		return nil, fmt.Errorf("unable to get 'api-key' from secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}
	netcupCfg.apiPassword, err = stringFromSecretData(&sec.Data, "api-password")
	if err != nil {
		return nil, fmt.Errorf("unable to get 'api-password' from secret '%s/%s': %v", secretNs, cfg.SecretRef, err)
	}

	return netcupCfg, nil
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
