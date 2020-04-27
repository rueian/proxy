licenses(["notice"])  # Apache 2

load(
    "@envoy_api//bazel:api_build_system.bzl",
    "api_cc_py_proto_library",
)

api_cc_py_proto_library(
    name = "npds",
    srcs = ["npds.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "@envoy_api//envoy/annotations:pkg",
        "@envoy_api//envoy/service/discovery/v3:pkg",
        "@envoy_api//envoy/config/core/v3:pkg",
        "@envoy_api//envoy/config/route/v3:pkg",
    ],
)

api_cc_py_proto_library(
    name = "nphds",
    srcs = ["nphds.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "@envoy_api//envoy/annotations:pkg",
        "@envoy_api//envoy/service/discovery/v3:pkg",
    ],
)
