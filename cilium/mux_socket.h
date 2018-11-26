#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/network/transport_socket.h"
#include "envoy/server/transport_socket_config.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/logger.h"
#include "common/common/lock_guard.h"
#include "common/common/thread.h"

namespace Envoy {
namespace Cilium {

extern std::string MuxSocketName;

class MuxSocketFactory : public Network::TransportSocketFactory {
public:
  MuxSocketFactory(bool upstream) : upstream_(upstream) {}

  // Network::TransportSocketFactory
  Network::TransportSocketPtr createTransportSocket() const override;
  bool implementsSecureTransport() const override;
private:
  MuxSocketFactory() {}
  bool upstream_;
};

union ShimTuple {
  bool operator==(const ShimTuple& other) const {
    return memcmp(this, &other, sizeof *this) == 0;
  }
  ShimTuple flip() const {
    ShimTuple id{};
    if (tuple_v6.dport_ != 0) /* IPV6 */ {
      id.tuple_v6.saddr_ = tuple_v6.daddr_;
      id.tuple_v6.daddr_ = tuple_v6.saddr_;
      id.tuple_v6.sport_ = tuple_v6.dport_;
      id.tuple_v6.dport_ = tuple_v6.sport_;
    } else {
      id.tuple_v4.saddr_ = tuple_v4.daddr_;
      id.tuple_v4.daddr_ = tuple_v4.saddr_;
      id.tuple_v4.sport_ = tuple_v4.dport_;
      id.tuple_v4.dport_ = tuple_v4.sport_;      
    }
    return id;
  }
  struct {
    uint32_t saddr_;
    uint32_t daddr_;
    uint16_t sport_;
    uint16_t dport_;
  } tuple_v4;
  struct {
    absl::uint128 saddr_;
    absl::uint128 daddr_;
    uint16_t sport_;
    uint16_t dport_;
  } tuple_v6;
  uint32_t _tuple_[9]; // addresses & ports
};

struct ShimHeader {
#if 0
  uint32_t length_; // frame length, NOT including this shim header
  ShimTuple id_;
#endif
};

class Mux;
class MuxData;
typedef std::unique_ptr<MuxData> MuxDataPtr;

class MuxSocket : public Network::TransportSocket, protected Logger::Loggable<Logger::Id::connection> {
public:
  MuxSocket(bool upstream) : upstream_(upstream) {}
  virtual ~MuxSocket();

  // Network::TransportSocket
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) override;
  std::string protocol() const override;
  bool canFlushClose() override { return true; }
  void closeSocket(Network::ConnectionEvent) override;
  void onConnected() override;
  Network::IoResult doRead(Buffer::Instance& buffer) override;
  Network::IoResult doWrite(Buffer::Instance& buffer, bool end_stream) override;
  const Ssl::Connection* ssl() const override { return nullptr; }

private:
  bool upstream_;
  MuxData* mux_data_{};
  Network::TransportSocketCallbacks* callbacks_{};
  bool shutdown_{};
  int fd_{-1};
};

typedef std::function<void(Network::ConnectionSocketPtr&&)> NewConnectionCB;
typedef std::function<void()> CloseMuxCB;

class Mux {
public:
  Mux(Event::Dispatcher& dispatcher, Network::ConnectionSocket& socket, NewConnectionCB addNewConnetion, CloseMuxCB closeMux, bool upstream);
  virtual ~Mux();

protected:
  friend class MuxSocket;
  void removeBuffer(int fd);

  // Read data from the muxed socket and demux it to "sockets_"
  // May be called from multiple threads
  void readAndDemux(bool upstream);
  Api::SysCallIntResult prependAndWrite(const ShimTuple& id, Buffer::Instance& buffer);

private:
  MuxData* addBuffer(const ShimTuple& id, bool upstream);

  void onRead();
  void onWrite();
  void onTimeout();
  void onClose();

  Network::ConnectionSocket& socket_;
  NewConnectionCB addNewConnection_;
  CloseMuxCB closeMux_;
  bool upstream_;

  // This lock MUST be acquired first if at all
  mutable Thread::MutexBasicLockable lock_;
  std::map<std::vector<uint32_t>, MuxDataPtr> buffers_ GUARDED_BY(lock_);
  Buffer::OwnedImpl read_buffer_ GUARDED_BY(lock_);  // partial input frames, whole frames will be moved to children
  MuxData* current_reader_{} GUARDED_BY(lock_); // partial input received for this socket, or NULL
  size_t remaining_read_length_{} GUARDED_BY(lock_); // How many more bytes needed for the current socket
  Buffer::OwnedImpl write_buffer_ GUARDED_BY(lock_);  // shim headers
  Event::FileEventPtr file_event_;
  Event::TimerPtr timer_;

  Mux* other{};  // ponter to the corresponding up/downstream mux.
};

typedef std::unique_ptr<Mux> MuxPtr;

/**
 * Config registration for the mux transport socket factory.
 * @see TransportSocketConfigFactory.
 */
class MuxSocketConfigFactory : public virtual Server::Configuration::TransportSocketConfigFactory {
public:
  virtual ~MuxSocketConfigFactory() {}
  std::string name() const override { return MuxSocketName; }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

class UpstreamMuxSocketConfigFactory
    : public Server::Configuration::UpstreamTransportSocketConfigFactory,
      public MuxSocketConfigFactory {
public:
  Network::TransportSocketFactoryPtr createTransportSocketFactory(
      const Protobuf::Message& config,
      Server::Configuration::TransportSocketFactoryContext& context) override;
};

class DownstreamMuxSocketConfigFactory
    : public Server::Configuration::DownstreamTransportSocketConfigFactory,
      public MuxSocketConfigFactory {
public:
  Network::TransportSocketFactoryPtr
  createTransportSocketFactory(const Protobuf::Message& config,
                               Server::Configuration::TransportSocketFactoryContext& context,
                               const std::vector<std::string>& server_names) override;
};

} // namespace Cilium
} // namespace Envoy
