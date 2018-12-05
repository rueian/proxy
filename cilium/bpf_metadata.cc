#include "cilium/bpf_metadata.h"
#include "cilium/api/bpf_metadata.pb.validate.h"

#include <string>

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
    auto* listenerConfig = &context.listenerConfig();
    context.addListenSocketOption(std::make_shared<Cilium::MuxListenSocketOption>(
	config->is_ingress_,
	[config, listenerConfig](Network::Socket& socket) -> bool {
	  if (config->use_kTLS_) {
	    Thread::LockGuard guard(config->lock_);
	    if (!config->upstream_socket_) {
	      ENVOY_LOG_MISC(trace, "UPSTREAM MUX creating socket for {}, fd {}!", listenerConfig->name(), socket.fd());
	      // Get the listening address and create a socket connecting to it.
	      config->upstream_socket_ = std::make_unique<Network::ClientSocketImpl>(listenerConfig->socket().localAddress());
	      ENVOY_LOG_MISC(trace, "UPSTREAM MUX socket {} CONNECTING!", config->upstream_socket_->fd());
	      const Api::SysCallIntResult result = config->upstream_socket_->remoteAddress()->connect(config->upstream_socket_->fd());
	      if (result.rc_ == -1 && result.errno_ != EINPROGRESS) {
		ENVOY_LOG_MISC(debug, "UPSTREAM MUX connect failure: {}", strerror(result.errno_));
		config->upstream_socket_.reset(nullptr);
		return false;
	      }
	    }
	  } else {
	    ENVOY_LOG_MISC(trace, "NOT USING MUX for {}", listenerConfig->name());
	  }
	  return true;
	}));

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

Instance::Instance(const ConfigSharedPtr& config)
    : config_(config) {
  ENVOY_LOG_MISC(trace, "UPSTREAM MUX creating instance");
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
    // Create the upstream mux on the same worker thread that accepts the downstream mux
    // Only one worker thread creates the upstream_socket_, so we only get one
    // worker thread ever accepting a kTLS mux connection!
    ENVOY_LOG_MISC(trace, "UPSTREAM MUX creating MUX!");
    upstream_mux_ = std::make_unique<Cilium::Mux>(cb_->dispatcher(),
						  *config_->upstream_socket_,
						  // add new connetion callback
						  [](Network::ConnectionSocketPtr&& sock) {
						    ENVOY_LOG_MISC(trace, "UPSTREAM MUX new connection callback on fd {}!", sock->fd());
						  },
						  // close accepted connection callback
						  []() {
						    ENVOY_LOG_MISC(trace, "UPSTREAM MUX close MUX connection callback!");
						  },
						  true /* upstream mux */);

    // Pass the connection to a new mux instance
    ENVOY_LOG(debug, "MUX test: New connection accepted on fd {}", socket.fd());

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

    // TODO: Register the socket pair with sockmap!
    
    return Network::FilterStatus::StopIteration;
  }
#if 0
  // Envoy inserts tls_inspector due to the setting of requiredApplicationProtocol to "tcp"
  // Some integrations tests fail with the tls_inspector inline, so we have stop
  // iteration and pass the connection on to bypass the tls_inspector filter.

  // Create a copy of the socket and pass it to newConnection callback.
  int fd2 = dup(socket.fd());
  ASSERT(fd2 >= 0, "dup() failed");

  Network::ConnectionSocketPtr sock = std::make_unique<Network::ConnectionSocketImpl>(fd2, socket.localAddress(), socket.remoteAddress());
  sock->addOptions(socket.options()); // copy a reference to the options on the original socket.
  if (socket.localAddressRestored()) {
    sock->setLocalAddress(socket.localAddress(), true);
  }
  ENVOY_LOG_MISC(trace, "newConnection on dupped fd {}", fd2);

  // Set detected application protocol to "tcp" if policy needs proxylib
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
