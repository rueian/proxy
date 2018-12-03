#include "cilium/bpf_metadata.h"
#include "cilium/api/bpf_metadata.pb.validate.h"

#include <string>

#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"

#include "common/common/assert.h"
#include "common/common/fmt.h"
#include "common/network/listen_socket_impl.h"

#include "cilium/socket_option.h"

#include <netinet/in.h>
#include <netinet/tcp.h>

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the bpf metadata filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class BpfMetadataConfigFactory : public NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
			       Configuration::ListenerFactoryContext& context) override {
    auto config = std::make_shared<Filter::BpfMetadata::Config>(MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(proto_config), context);
    // Set the socket mark option for the listen socket.
    // Can use identity 0 on the listen socket option, as the bpf datapath is only interested
    // in whether the proxy is ingress, egress, or if there is no proxy at all.
    context.addListenSocketOption(std::make_shared<Cilium::SocketMarkOption>(0, config->is_ingress_));

    return [config](Network::ListenerFilterManager &filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(std::make_unique<Filter::BpfMetadata::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::BpfMetadata>();
  }

  std::string name() override { return "cilium.bpf_metadata"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<BpfMetadataConfigFactory,
                                 NamedListenerFilterConfigFactory>
    registered_;

} // namespace Configuration
} // namespace Server

namespace Filter {
namespace BpfMetadata {

// Singleton registration via macro defined in envoy/singleton/manager.h
SINGLETON_MANAGER_REGISTRATION(cilium_bpf_proxymap);
SINGLETON_MANAGER_REGISTRATION(cilium_host_map);
SINGLETON_MANAGER_REGISTRATION(cilium_network_policy);

namespace {

std::shared_ptr<const Cilium::PolicyHostMap>
createHostMap(Server::Configuration::ListenerFactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::PolicyHostMap>(
    SINGLETON_MANAGER_REGISTERED_NAME(cilium_host_map), [&context] {
      auto map = std::make_shared<Cilium::PolicyHostMap>(
          context.localInfo(), context.clusterManager(),
	  context.dispatcher(), context.random(), context.scope(),
	  context.threadLocal());
      map->startSubscription();
      return map;
    });
}

std::shared_ptr<const Cilium::NetworkPolicyMap>
createPolicyMap(Server::Configuration::FactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::NetworkPolicyMap>(
    SINGLETON_MANAGER_REGISTERED_NAME(cilium_network_policy), [&context] {
      auto map = std::make_shared<Cilium::NetworkPolicyMap>(
	  context.localInfo(), context.clusterManager(),
	  context.dispatcher(), context.random(), context.scope(),
	  context.threadLocal());
      map->startSubscription();
      return map;
    });
}

} // namespace

Config::Config(const ::cilium::BpfMetadata &config, Server::Configuration::ListenerFactoryContext& context)
    : is_ingress_(config.is_ingress()), use_kTLS_(config.use_ktls()) {
  // Note: all instances use the bpf root of the first filter with non-empty bpf_root instantiated!
  std::string bpf_root = config.bpf_root();
  if (bpf_root.length() > 0) {
    maps_ = context.singletonManager().getTyped<Cilium::ProxyMap>(
        SINGLETON_MANAGER_REGISTERED_NAME(cilium_bpf_proxymap), [&bpf_root] {
	  return std::make_shared<Cilium::ProxyMap>(bpf_root);
	});
    if (bpf_root != maps_->bpfRoot()) {
      throw EnvoyException(fmt::format("cilium.bpf_metadata: Invalid bpf_root: {}", bpf_root));
    }
  }
  hosts_ = createHostMap(context);

  // Get the shared policy provider, or create it if not already created.
  // Note that the API config source is assumed to be the same for all filter instances!
  npmap_ = createPolicyMap(context);
}

bool Config::getMetadata(Network::ConnectionSocket& socket) {
  uint32_t source_identity, destination_identity = Cilium::ID::WORLD;
  uint16_t orig_dport, proxy_port;
  bool ok = false;

  if (maps_) {
    ok = maps_->getBpfMetadata(socket, &source_identity, &orig_dport, &proxy_port);
  } else if (hosts_ && socket.remoteAddress()->ip() && socket.localAddress()->ip()) {
    // Resolve the source security ID
    source_identity = hosts_->resolve(socket.remoteAddress()->ip());
    // assume original address has been restored
    orig_dport = socket.localAddress()->ip()->port();
    proxy_port = 0; // no proxy_port when no bpf.
    ok = true;
  }
  std::string pod_ip;
  if (is_ingress_ && socket.localAddress()->ip()) {
    pod_ip = socket.localAddress()->ip()->addressAsString();
    ENVOY_LOG_MISC(debug, "INGRESS POD_IP: {}", pod_ip);
  } else if (!is_ingress_ && socket.remoteAddress()->ip()) {
    pod_ip = socket.remoteAddress()->ip()->addressAsString();
    ENVOY_LOG_MISC(debug, "EGRESS POD_IP: {}", pod_ip);
  }
  if (ok) {
    // Resolve the destination security ID
    if (hosts_ && socket.localAddress()->ip()) {
      destination_identity = hosts_->resolve(socket.localAddress()->ip());
    }
    socket.addOption(std::make_shared<Cilium::SocketOption>(npmap_, maps_, source_identity, destination_identity, is_ingress_, orig_dport, proxy_port, std::move(pod_ip)));
  }

  return ok;
}

Instance::Instance(const ConfigSharedPtr& config) : config_(config) {
  // Should create upstream mux here and connect it to the listening address
}

Network::FilterStatus Instance::onAccept(Network::ListenerFilterCallbacks &cb) {
  Network::ConnectionSocket &socket = cb.socket();
  if (!config_->getMetadata(socket)) {
    ENVOY_LOG(debug,
              "cilium.bpf_metadata ({}): NO metadata for the connection",
              config_->is_ingress_ ? "ingress" : "egress");
  } else {
    ENVOY_LOG(trace,
              "cilium.bpf_metadata ({}): GOT metadata for new connection",
              config_->is_ingress_ ? "ingress" : "egress");
  }

  // Set socket options for linger and keepalive (5 minutes).
  int rc;
  struct ::linger lin{ true, 10 };
  int keepalive = true;
  int secs = 5*60; // Five minutes

  rc = setsockopt(socket.fd(), SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
  if (rc < 0) {
    ENVOY_LOG(critical, "Socket option failure. Failed to set SO_LINGER: {}", strerror(errno));
  }
  rc = setsockopt(socket.fd(), SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
  if (rc < 0) {
    ENVOY_LOG(critical, "Socket option failure. Failed to set SO_KEEPALIVE: {}", strerror(errno));
  } else {
    rc = setsockopt(socket.fd(), IPPROTO_TCP, TCP_KEEPINTVL, &secs, sizeof(secs));
    if (rc < 0) {
      ENVOY_LOG(critical, "Socket option failure. Failed to set TCP_KEEPINTVL: {}",
		strerror(errno));
    } else {
      rc = setsockopt(socket.fd(), IPPROTO_TCP, TCP_KEEPIDLE, &secs, sizeof(secs));
      if (rc < 0) {
	ENVOY_LOG(critical, "Socket option failure. Failed to set TCP_KEEPIDLE: {}",
		  strerror(errno));
      }
    }
  }

  cb_ = &cb;

  if (config_->use_kTLS_) {
    // Terminate the accept filter chain when the socket gets closed.
    ENVOY_LOG(debug, "MUX test: New connection accepted");

    mux_ = std::make_unique<Cilium::Mux>(cb_->dispatcher(), socket,
					 // add new connetion callback
					 [this](Network::ConnectionSocketPtr&& sock) {
					   // Set detected application protocol to "tcp" if policy needs proxylib
					   const auto option = Cilium::GetSocketOption(sock->options());
					   if (option) {
					     std::string l7proto;
					     if (option->npmap_->useProxylib(option->pod_ip_, option->ingress_, option->port_, l7proto)) {
					       std::vector<absl::string_view> protocols{"tcp"};
					       sock->setRequestedApplicationProtocols(protocols);
					     }
					   }
					   cb_->newConnection(std::move(sock));
					 },
					 // close accepted connection callback
					 [this]() {
					   stopped_ = false;
					   cb_->continueFilterChain(false);
					 },
					 false /* downstream mux */);

    stopped_ = true;
    return Network::FilterStatus::StopIteration;
  }
#if 1
  // Create a copy of the socket and pass it to newConnection callback.
  int fd2 = dup(socket.fd());
  ASSERT(fd2 >= 0, "dup() failed");

  Network::ConnectionSocketPtr sock = std::make_unique<Network::ConnectionSocketImpl>(fd2, socket.localAddress(), socket.remoteAddress());
  sock->addOptions(socket.options()); // copy a referene to the options on the original socket.
  if (socket.localAddressRestored()) {
    sock->setLocalAddress(socket.localAddress(), true);
  }
  ENVOY_LOG_MISC(trace, "newConnection on dupped fd {}", fd2);

  // Set detected application protocol to "tcp" if policy needs proxylib
  // TODO: Check we don't collide with tls_inspector!
  const auto option = Cilium::GetSocketOption(sock->options());
  if (option) {
    std::string l7proto;
    if (option->npmap_->useProxylib(option->pod_ip_, option->ingress_, option->port_, l7proto)) {
      std::vector<absl::string_view> protocols{"tcp"};
      sock->setRequestedApplicationProtocols(protocols);
    }
  }
  stopped_ = true;
  cb_->newConnection(std::move(sock));
  return Network::FilterStatus::StopIteration;
#else
  return Network::FilterStatus::Continue;
#endif
}

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
