#!/bin/bash

docker run \
  --volume "$(pwd):/go/src/github.com/cilium/cilium/envoy" \
  --workdir "/go/src/github.com/cilium/cilium/envoy" \
  docker.io/errordeveloper/image-compilers:7c86e798a5c95080b7f8bd3102b070fb941ba54f-dev  \
    bazel build \
      --jobs=3 \
      --verbose_failures \
      --local_resources 4096,2.0,1.0 \
      -c opt //:cilium-envoy 
