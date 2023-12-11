# (first line comment needed for DOCKER_BUILDKIT use)
#
# use skopeo inspect to get the multiarch manifest list digest
# skopeo inspect --override-os linux docker://golang:1.21.5-alpine3.19 | jq -r '.Digest'
ARG GOLANG_IMAGE=docker.io/library/golang:1.21.5-alpine3.19@sha256:feceecc0e1d73d085040a8844de11a2858ba4a0c58c16a672f1736daecc2a4ff
ARG BASE_IMAGE=scratch

FROM ${GOLANG_IMAGE} as builder
ADD . /go/src/github.com/cilium/certgen
WORKDIR /go/src/github.com/cilium/certgen
RUN CGO_ENABLED=0 go build -o cilium-certgen main.go

FROM ${BASE_IMAGE}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/certgen/cilium-certgen /usr/bin/cilium-certgen
ENTRYPOINT ["/usr/bin/cilium-certgen"]
