# (first line comment needed for DOCKER_BUILDKIT use)
#
# use skopeo inspect to get the multiarch manifest list digest
# skopeo inspect --override-os linux docker://<GOLANG_IMAGE> | jq -r '.Digest'
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.4-alpine3.22@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56

ARG BASE_IMAGE=scratch

FROM ${GOLANG_IMAGE} AS builder
ADD . /go/src/github.com/cilium/certgen
WORKDIR /go/src/github.com/cilium/certgen
RUN apk add --no-cache binutils make
RUN make certgen

FROM ${BASE_IMAGE}
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/certgen/certgen /usr/bin/cilium-certgen
ENTRYPOINT ["/usr/bin/cilium-certgen"]
