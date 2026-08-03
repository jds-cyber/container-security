FROM registry.access.redhat.com/hi/grype:latest

USER 0

COPY zscaler-root-ca.crt /etc/pki/ca-trust/source/anchors/zscaler-root-ca.crt

RUN update-ca-trust

USER 1000

