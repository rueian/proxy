#include "ktlsmaps.h"

#include <string.h>

#include "linux/bpf.h"

namespace Envoy {
namespace Cilium {

KTLSMaps::KTLSMap::KTLSMap()
  : Bpf(BPF_MAP_TYPE_SOCKMAP, sizeof(int), sizeof(int)) {}

KTLSMaps::KTLSMaps(const std::string &bpf_root)
  : bpf_root_(bpf_root) {
  // Open the bpf maps from Cilium specific paths

  std::string down_path(bpf_root_ + "/tc/globals/sock_ops_ktls_down");
  if (!downmap_.open(down_path)) {
    ENVOY_LOG(info, "cilium.bpf_metadata: Cannot open kTLS upstream map at {}", down_path);
  }

  std::string up_path(bpf_root_ + "/tc/globals/sock_ops_ktls_up");
  if (!upmap_.open(up_path)) {
    ENVOY_LOG(info, "cilium.bpf_metadata: Cannot open kTLS downstream map at {}", up_path);
  }

  ENVOY_LOG(trace, "cilium.bpf_metadata: Created kTLSMaps.");
}

bool KTLSMaps::registerMuxSockets(int upstream_fd, int downstream_fd) {
  int i = 0;
  bool ok = true;
  // At least for Egress. May be reversed for ingress?
  if (!downmap_.insert(&i, &downstream_fd)) {
    ENVOY_LOG(info, "cilium.bpf_metadata: Upstream kTLS map update failed: {}",
	      strerror(errno));
    ok = false;
  }
  if (!upmap_.insert(&i, &upstream_fd)) {
    ENVOY_LOG(info, "cilium.bpf_metadata: Downstream kTLS map update failed: {}",
	      strerror(errno));
    ok = false;
  }
  
  return ok;
}

bool KTLSMaps::unregisterMuxSockets() {
  int i = 0;
  bool ok = true;
  if (!upmap_.remove(&i)) {
    ENVOY_LOG(info, "cilium.bpf_metadata: Upstream kTLS map remove failed: {}",
	      strerror(errno));
    ok = false;
  }
  if (!downmap_.remove(&i)) {
    ENVOY_LOG(info, "cilium.bpf_metadata: Downstream kTLS map remove failed: {}",
	      strerror(errno));
    ok = false;
  }
  
  return ok;
}

} // namespace Cilium
} // namespace Envoy
