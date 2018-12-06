#pragma once

#include "common/common/logger.h"
#include "envoy/singleton/instance.h"

#include "bpf.h"

namespace Envoy {
namespace Cilium {

class KTLSMaps : public Singleton::Instance, Logger::Loggable<Logger::Id::filter> {
public:
  KTLSMaps(const std::string &bpf_root);
  ~KTLSMaps() {
    unregisterMuxSockets();
  }

  const std::string& bpfRoot() { return bpf_root_; }

  bool registerMuxSockets(int upstream_fd, int downstream_fd);
  bool unregisterMuxSockets();

private:
  class KTLSMap : public Bpf {
  public:
    KTLSMap();
  };

  std::string bpf_root_;
  KTLSMap upmap_;
  KTLSMap downmap_;
};

typedef std::shared_ptr<KTLSMaps> KTLSMapsSharedPtr;
 
} // namespace Cilium
} // namespace Envoy
