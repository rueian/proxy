#include "cilium/network_filter.h"

#include <dlfcn.h>

#include "cilium/api/network_filter.pb.validate.h"
#include "cilium/socket_option.h"
#include "common/buffer/buffer_impl.h"
#include "common/common/assert.h"
#include "common/common/fmt.h"
#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the bpf metadata filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class CiliumNetworkConfigFactory : public NamedNetworkFilterConfigFactory {
 public:
  // NamedNetworkFilterConfigFactory
  Network::FilterFactoryCb createFilterFactoryFromProto(
      const Protobuf::Message& proto_config, FactoryContext& context) override {
    auto config = std::make_shared<Filter::CiliumL3::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::NetworkFilter&>(
            proto_config, context.messageValidationVisitor()),
        context);
    return [config](Network::FilterManager& filter_manager) mutable -> void {
      filter_manager.addFilter(
          std::make_shared<Filter::CiliumL3::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::NetworkFilter>();
  }

  std::string name() const override { return "cilium.network"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<CiliumNetworkConfigFactory,
                                 NamedNetworkFilterConfigFactory>
    registered_;

}  // namespace Configuration
}  // namespace Server

namespace Filter {
namespace CiliumL3 {

Config::Config(const ::cilium::NetworkFilter& config,
               Server::Configuration::FactoryContext& context)
    : time_source_(context.timeSource()) {
  // const auto& access_log_path = config.access_log_path();
  // if (access_log_path.length()) {
  //   access_log_ = Cilium::AccessLog::Open(access_log_path);
  //   if (!access_log_) {
  //     ENVOY_LOG(warn, "Cilium filter can not open access log socket {}",
  //               access_log_path);
  //   }
  // }
  if (config.proxylib().length() > 0) {
    proxylib_ = std::make_shared<Cilium::GoFilter>(config.proxylib(),
                                                   config.proxylib_params());
  }
  // if (config.policy_name() != "" || config.l7_proto() != "") {
  //   throw EnvoyException(fmt::format("network: 'policy_name' and 'go_proto'
  //   are no longer supported: \'{}\'", config.DebugString()));
  // }
}

Config::~Config() {
  if (access_log_) {
    access_log_->Close();
  }
}

void Config::Log(Cilium::AccessLog::Entry& entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->Log(entry, type);
  }
}

Network::FilterStatus Instance::onNewConnection() {
  ENVOY_LOG(debug, "Cilium Network: onNewConnection");
  auto& conn = callbacks_->connection();

  if (config_->proxylib_.get() != nullptr) {
    go_parser_ = config_->proxylib_->NewInstance(
        conn, conn.remoteAddress()->asString(),
        conn.localAddress()->asString());
    if (go_parser_.get() == nullptr) {
      ENVOY_CONN_LOG(warn, "Cilium Network: Go parser \"{}\" not found",
                      conn, "");
      return Network::FilterStatus::StopIteration;
    }
  }

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onData(Buffer::Instance& data,
                                       bool end_stream) {
  auto& conn = callbacks_->connection();
  if (go_parser_) {
    FilterResult res = go_parser_->OnIO(
        false, data, end_stream);  // 'false' marks original direction data
    ENVOY_CONN_LOG(trace,
                   "Cilium Network::onData: \'GoFilter::OnIO\' returned {}",
                   conn, res);

    if (res != FILTER_OK) {
      // Drop the connection due to an error
      go_parser_->Close();
      conn.close(Network::ConnectionCloseType::NoFlush);
      return Network::FilterStatus::StopIteration;
    }

    if (go_parser_->WantReplyInject()) {
      ENVOY_CONN_LOG(
          trace, "Cilium Network::onData: calling write() on an empty buffer",
          conn);

      // We have no idea when, if ever new data will be received on the
      // reverse direction. Connection write on an empty buffer will cause
      // write filter chain to be called, and gives our write path the
      // opportunity to inject data.
      Buffer::OwnedImpl empty;
      conn.write(empty, false);
    }

    go_parser_->SetOrigEndStream(end_stream);
  }

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onWrite(Buffer::Instance& data,
                                        bool end_stream) {
  if (go_parser_) {
    FilterResult res = go_parser_->OnIO(
        true, data, end_stream);  // 'true' marks reverse direction data
    ENVOY_CONN_LOG(trace,
                   "Cilium Network::OnWrite: \'GoFilter::OnIO\' returned {}",
                   callbacks_->connection(), res);

    if (res != FILTER_OK) {
      // Drop the connection due to an error
      go_parser_->Close();
      return Network::FilterStatus::StopIteration;
    }

    // XXX: Unfortunately continueReading() continues from the next filter, and
    // there seems to be no way to trigger the whole filter chain to be called.

    go_parser_->SetReplyEndStream(end_stream);
  }

  return Network::FilterStatus::Continue;
}



}  // namespace CiliumL3
}  // namespace Filter
}  // namespace Envoy
