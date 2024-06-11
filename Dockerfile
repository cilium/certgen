# (first line comment needed for DOCKER_BUILDKIT use)
#
# use skopeo inspect to get the multiarch manifest list digest
# skopeo inspect --override-os linux docker://golang:1.22.4-alpine3.19 | jq -r '.Digest'
ARG GOLANG_IMAGE=docker.io/library/golang:1.22.4-alpine3.19@sha256:65b5d2d0a312fd9ef65551ad7f9cb5db1f209b7517ef6d5625cfd29248bc6c85
ARG BASE_IMAGE=scratch

FROM ${GOLANG_IMAGE} as builder
ADD . /go/src/github.com/cilium/certgen
WORKDIR /go/src/github.com/cilium/certgen
RUN CGO_ENABLED=0 go build -o cilium-certgen main.go

FROM ${BASE_IMAGE}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/certgen/cilium-certgen /usr/bin/cilium-certgen
ENTRYPOINT ["/usr/bin/cilium-certgen"]
