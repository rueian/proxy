workspace(name = "cilium")

#
# We grep for the following line to generate SOURCE_VERSION file for non-git
# distribution builds. This line must start with the string ENVOY_SHA followed by
# an equals sign and a git SHA in double quotes.
#
# No other line in this file may have ENVOY_SHA followed by an equals sign!
#
ENVOY_SHA = "b5c068ee2a087818f07b2dce0debd2de7983607e"
ENVOY_SHA256 = "1fd53be21de08cd0329694c9df4232ccf1a7ef280de09d2615ebc4d0416fa39a"

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Dependencies for Istio filters.
# Cf. https://github.com/istio/proxy.
# Version 1.4.5
ISTIO_PROXY_SHA = "2369b2f31802ab74d942462ed21a00e3a38de2c5"
ISTIO_PROXY_SHA256 = "069c7f98d9549da98156fe48de5e18aad43af446445bfee6429fbc5605d8d64a"

http_archive(
    name = "istio_proxy",
    url = "https://github.com/istio/proxy/archive/" + ISTIO_PROXY_SHA + ".tar.gz",
    sha256 = ISTIO_PROXY_SHA256,
    strip_prefix = "proxy-" + ISTIO_PROXY_SHA,
    patches = [
        "@//patches:istio-add-fallthrough.patch",
    ],
    patch_args = ["-p1"],
)

load(
    "@istio_proxy//:repositories.bzl",
    "docker_dependencies",
    "googletest_repositories",
    "mixerapi_dependencies",
)
googletest_repositories()
mixerapi_dependencies()

bind(
    name = "boringssl_crypto",
    actual = "//external:ssl",
)

http_archive(
    name = "envoy",
    url = "https://github.com/istio/envoy/archive/" + ENVOY_SHA + ".tar.gz",
    sha256 = ENVOY_SHA256,
    strip_prefix = "envoy-" + ENVOY_SHA,
    patches = [
        "@//patches:envoy-original-dst-add-sni.patch",
        "@//patches:envoy-test-enable-half-close.patch",
        "@//patches:envoy-add-add-get-transport-socket-factory-context.patch",
        "@//patches:envoy-connection-pass-socket-options-upstream.patch",
    ],
    patch_args = ["-p1"],
)

#
# Bazel does not do transitive dependencies, so we must basically
# include all of Envoy's WORKSPACE file below, with the following
# changes:
# - Skip the 'workspace(name = "envoy")' line as we already defined
#   the workspace above.
# - loads of "//..." need to be renamed as "@envoy//..."
#

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")
envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")
envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")
envoy_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")
envoy_dependency_imports()

# Docker dependencies

docker_dependencies()

load(
    "@io_bazel_rules_docker//repositories:repositories.bzl",
    container_repositories = "repositories",
)

container_repositories()

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")

container_deps()

load(
    "@io_bazel_rules_docker//container:container.bzl",
    "container_pull",
)

container_pull(
    name = "distroless_cc",
    # Latest as of 10/21/2019. To update, remove this line, re-build, and copy the suggested digest.
    digest = "sha256:86f16733f25964c40dcd34edf14339ddbb2287af2f7c9dfad88f0366723c00d7",
    registry = "gcr.io",
    repository = "distroless/cc",
)

container_pull(
    name = "bionic",
    # Latest as of 10/21/2019. To update, remove this line, re-build, and copy the suggested digest.
    digest = "sha256:3e83eca7870ee14a03b8026660e71ba761e6919b6982fb920d10254688a363d4",
    registry = "index.docker.io",
    repository = "library/ubuntu",
    tag = "bionic",
)

# End of docker dependencies
