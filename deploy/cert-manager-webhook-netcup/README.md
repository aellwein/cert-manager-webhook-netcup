cert-manager-webhook-netcup
===========================

[cert-manager](https://cert-manager.io) webhook implementation for use
with [Netcup](https://www.netcup.eu) provider for solving [ACME DNS-01
challenges](https://cert-manager.io/docs/configuration/acme/dns01/).

Usage
-----

For the netcup-specific configuration, you will need to create a Kubernetes
secret, containing your customer number, API key and API password first.

You can do it like following, just place the correct values in the command:

```sh
kubectl create secret generic netcup-secret -n cert-manager --from-literal=customer-number=<your-customer-number> --from-literal=api-key=<api-key-from-netcup-dashboard> --from-literal=api-password=<api-password-from-netcup-dashboard>
```
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
helm repo add cert-manager-webhook-netcup https://aellwein.github.io/cert-manager-webhook-netcup/charts/

helm install my-cert-manager-webhook-netcup cert-manager-webhook-netcup/cert-manager-webhook-netcup --namespace cert-manager
```
From that point, the issuer configured above should be able to solve
the DNS01 challenges using ``cert-manager-webhook-netcup``.


Disclaimer
----------

I am in no way affiliated or associated with Netcup and this project
is done in my spare time.


License
-------

[Apache 2 License](./LICENSE)



