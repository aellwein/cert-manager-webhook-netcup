cert-manager-webhook-netcup
===========================

Helm chart for installation of cert-manager's webhook for solving DNS challenges using Netcup DNS API.

See this [README.md](https://github.com/aellwein/cert-manager-webhook-netcup/blob/master/README.md) 
for configuration and more details.

Release
-------

* Run this directory:
  ```
  helm package ../deploy/cert-manager-webhook-netcup && helm repo index .
  ```
* Add build artifact and index.yaml to git and commit to this branch.