#!/bin/sh

helm package ../deploy/cert-manager-webhook-netcup && \
find . -name "*.tgz" | while read f; do \
helm gpg sign $f ; helm gpg verify $f ; done && \
helm repo index .
