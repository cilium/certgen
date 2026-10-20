# (first line comment needed for DOCKER_BUILDKIT use)
#
# use skopeo inspect to get the multiarch manifest list digest
# skopeo inspect --override-os linux docker://<GOLANG_IMAGE> | jq -r '.Digest'
ARG GOLANG_IMAGE=docker.io/library/golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd


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
