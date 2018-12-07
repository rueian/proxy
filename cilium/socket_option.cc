#include "cilium/socket_option.h"

namespace Envoy {
namespace Cilium {

std::atomic<uint64_t> MuxSocketOption::root{};

} // namespace Cilium
} // namespace Envoy
