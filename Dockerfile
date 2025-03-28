# (first line comment needed for DOCKER_BUILDKIT use)
#
# use skopeo inspect to get the multiarch manifest list digest
# skopeo inspect --override-os linux docker://golang:1.23.7-alpine3.21 | jq -r '.Digest'
ARG GOLANG_IMAGE=docker.io/library/golang:1.23.7-alpine3.21@sha256:e438c135c348bd7677fde18d1576c2f57f265d5dfa1a6b26fca975d4aa40b3bb
ARG BASE_IMAGE=scratch

FROM ${GOLANG_IMAGE} AS builder
ADD . /go/src/github.com/cilium/certgen
WORKDIR /go/src/github.com/cilium/certgen
RUN CGO_ENABLED=0 go build -o cilium-certgen main.go

FROM ${BASE_IMAGE}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/certgen/cilium-certgen /usr/bin/cilium-certgen
ENTRYPOINT ["/usr/bin/cilium-certgen"]
