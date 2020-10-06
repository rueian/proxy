# Copyright 2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

REGISTRIES ?= quay.io/cilium

PUSH ?= false

OUTPUT := "type=image"
ifeq ($(PUSH),true)
OUTPUT := "type=registry,push=true"
endif

all-images: lint cilium-envoy-image

lint:
	scripts/lint.sh

.buildx_builder:
	# see https://github.com/docker/buildx/issues/308
	mkdir -p ../.buildx
	docker buildx create --platform linux/amd64,linux/arm64 --buildkitd-flags '--debug' > $@

.PHONY: cilium-envoy-image

cilium-envoy-image: .buildx_builder
	ROOT_CONTEXT=true scripts/build-image.sh cilium-envoy-dev images/cilium-envoy linux/amd64 $(OUTPUT) "$$(cat .buildx_builder)" $(REGISTRIES)
