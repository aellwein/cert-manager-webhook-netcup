[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager-webhook-netcup)](https://artifacthub.io/packages/helm/cert-manager-webhook-netcup/cert-manager-webhook-netcup)
[![Go Report Card](https://goreportcard.com/badge/github.com/aellwein/cert-manager-webhook-netcup)](https://goreportcard.com/report/github.com/aellwein/cert-manager-webhook-netcup)
[![License](https://img.shields.io/github/license/aellwein/cert-manager-webhook-netcup)](https://github.com/aellwein/cert-manager-webhook-netcup/blob/main/LICENSE)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/aellwein/cert-manager-webhook-netcup)


cert-manager-webhook-netcup
===========================

> ‼️ **Important Note:**
>
> beginning with the version `1.0.45`, all releases are available only via OCI registry:
>
> **[oci://ghcr.io/aellwein/cert-manager-webhook-netcup](https://github.com/aellwein/cert-manager-webhook-netcup/pkgs/container/cert-manager-webhook-netcup%2Fcert-manager-webhook-netcup)**
>
>

[cert-manager](https://cert-manager.io) webhook implementation for use
with [Netcup](https://www.netcup.eu) provider for solving [ACME DNS-01
challenges](https://cert-manager.io/docs/configuration/acme/dns01/).

Usage
-----

For the netcup-specific configuration, you will need to create a Kubernetes
secret containing your netcup API credentials first.

netcup offers two APIs, and the webhook selects one based on what the secret
contains.

The **REST API** (``api.netcup.com``), used for domains on netcup's current
DNS backend, needs only an API key:

```sh
kubectl create secret generic netcup-secret -n cert-manager --from-literal=api-key=<api-key-from-netcup-dashboard>
```

The **legacy CCP API** needs a customer number, API key and API password:

```sh
kubectl create secret generic netcup-secret -n cert-manager --from-literal=customer-number=<your-customer-number> --from-literal=api-key=<api-key-from-netcup-dashboard> --from-literal=api-password=<api-password-from-netcup-dashboard>
```

If ``customer-number`` and ``api-password`` are present, the legacy API is
used; otherwise the REST API.

To move an existing installation to the REST API, replace ``api-key`` with
your REST API key and remove the other two entries. The secret is read on
every challenge, so nothing needs restarting.
After creating the secret, configure the ``Issuer``/``ClusterIssuer`` of
yours to have the following configuration (as assumed, secret is
called "netcup-secret" and located in namespace "cert-manager"):

```yml
apiVersion: cert-manager.io/v1
kind: Issuer   # may also be a ClusterIssuer
...
spec:
    solvers:
    - dns01:
        webhook:
            groupName: com.netcup.webhook
            solverName: netcup
            config:
                secretRef: netcup-secret
                secretNamespace: cert-manager
```
For more details, please refer to https://cert-manager.io/docs/configuration/acme/dns01/#configuring-dns01-challenge-provider

Now, the actual webhook can be installed via Helm chart:
```
helm install webhook-netcup oci://ghcr.io/aellwein/cert-manager-webhook-netcup/cert-manager-webhook-netcup --namespace cert-manager
```
From that point, the issuer configured above should be able to solve
the DNS01 challenges using ``cert-manager-webhook-netcup``.


Domains on different netcup backends
------------------------------------

A domain is managed either through the REST API or through the legacy CCP
API, never both, and an account can hold some of each while netcup migrates.
Since the secret selects one API, such an account needs a separate solver or
``Issuer`` per API, each naming its own secret and selected by ``dnsZones``.

CNAME delegation
----------------

With ``cnameStrategy: Follow``, cert-manager resolves the CNAME chain itself
and asks the webhook to write the record at the target name. The ACME
endpoints of the REST API can only manage ``_acme-challenge`` records, so the
target has to be one:

```
# works
_acme-challenge.example.com.  CNAME  _acme-challenge.example-com.delegated.de.

# rejected: the target carries no _acme-challenge prefix
_acme-challenge.example.com.  CNAME  validation.delegated.de.
```

The legacy CCP API has no such restriction. A delegation to a prefix-less
target therefore needs legacy credentials for that domain, and switching such
a setup from legacy credentials to a REST key will stop it working.


Disclaimer
----------

I am in no way affiliated or associated with Netcup and this project
is done in my spare time.


License
-------

[Apache 2 License](./LICENSE)



