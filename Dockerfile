# (first line comment needed for DOCKER_BUILDKIT use)
#
# use skopeo inspect to get the multiarch manifest list digest
# skopeo inspect --override-os linux docker://golang:1.25.3-alpine3.22 | jq -r '.Digest'
ARG GOLANG_IMAGE=docker.io/library/golang:1.25.3-alpine3.22@sha256:aee43c3ccbf24fdffb7295693b6e33b21e01baec1b2a55acc351fde345e9ec34

ARG BASE_IMAGE=scratch

FROM ${GOLANG_IMAGE} AS builder
ADD . /go/src/github.com/cilium/certgen
WORKDIR /go/src/github.com/cilium/certgen
RUN CGO_ENABLED=0 go build -o cilium-certgen main.go

FROM ${BASE_IMAGE}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/certgen/cilium-certgen /usr/bin/cilium-certgen
ENTRYPOINT ["/usr/bin/cilium-certgen"]
