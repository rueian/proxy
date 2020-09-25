# syntax=docker/dockerfile:1.1-experimental

# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=docker.io/cilium/image-compilers:32a185376865d6cb0f82d7339e311d998ab859c1

FROM quay.io/cilium/cilium-envoy-builder:a31e6f62f344735d9b23763f9855c06e0569916b@sha256:ab94eba1d5665c48163646c3696b3732a32d6192053c2b7260ce5171da90fedd as cache

FROM --platform=linux/amd64 ${COMPILERS_IMAGE} as builder
COPY --from=cache /root/.cache /root/.cache
ARG TARGETPLATFORM

ARG BAZEL_BUILD_OPTS="--jobs=3 --local_ram_resources 4096 --verbose_failures"
WORKDIR /src

RUN --mount=type=bind,readwrite,target=/src \
  make cilium-envoy install \
  BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS}" \
  PKG_BUILD=1 \
  DESTDIR=/out/linux/amd64

RUN --mount=type=bind,readwrite,target=/src \
  make cilium-envoy install \
  BAZEL_BUILD_OPTS="${BAZEL_BUILD_OPTS} --incompatible_enable_cc_toolchain_resolution --platforms=//bazel/platforms:aarch64_cross --record_rule_instantiation_callstack --define cross=aarch64" \
  STRIP=aarch64-linux-gnu-strip \
  PKG_BUILD=1 \
  DESTDIR=/out/linux/arm64

FROM scratch
ARG TARGETPLATFORM
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /out/${TARGETPLATFORM} /
