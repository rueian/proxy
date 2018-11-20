#pragma once

#include "envoy/event/file_event.h"
#include "envoy/event/timer.h"
#include "envoy/json/json_object.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"

#include "common/common/logger.h"

#include "cilium/api/bpf_metadata.pb.h"
#include "cilium/proxymap.h"
#include "cilium/host_map.h"
#include "cilium/mux_socket.h"

namespace Envoy {
namespace Filter {
namespace BpfMetadata {

/**
 * Global configuration for Bpf Metadata listener filter. This
 * represents all global state shared among the working thread
 * instances of the filter.
 */
class Config : Logger::Loggable<Logger::Id::config> {
public:
  Config(const ::cilium::BpfMetadata &config, Server::Configuration::ListenerFactoryContext& context);
  virtual ~Config() {}

  virtual bool getMetadata(Network::ConnectionSocket &socket);

  bool is_ingress_;
  Cilium::ProxyMapSharedPtr maps_{};
  std::shared_ptr<const Cilium::PolicyHostMap> hosts_;
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

/**
 * Implementation of a bpf metadata listener filter.
 */
class Instance : public Network::ListenerFilter,
                 Logger::Loggable<Logger::Id::filter> {
public:
  Instance(const ConfigSharedPtr& config);
  ~Instance() {
    if (stopped_) {
      cb_->continueFilterChain(false);
    }
  }

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks &cb) override;

private:
  const ConfigSharedPtr config_;
  bool stopped_{false};
  Network::ListenerFilterCallbacks* cb_{};
  Cilium::MuxPtr mux_;
  Cilium::MuxPtr upstream_mux_;
};

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
