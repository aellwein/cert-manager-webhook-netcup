#!/bin/sh

helm package ../deploy/cert-manager-webhook-netcup && \
find . -name "*.tgz" | while read f; do \
if [ ! -e "$f.prov" ]; then helm gpg sign $f ; helm gpg verify $f ; fi; done && \
helm repo index .
