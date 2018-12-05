#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/network/transport_socket.h"
#include "envoy/server/transport_socket_config.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/logger.h"
#include "common/common/lock_guard.h"
#include "common/common/thread.h"
#include "common/network/address_impl.h"

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

struct ShimTuple {
  ShimTuple(const Network::Address::Ip* src, const Network::Address::Ip* dst) {
    memset(this, 0, sizeof(*this));
    if (src && dst && src->ipv4() && dst->ipv4()) {
      family_ = AF_INET;
      sip4_ = src->ipv4()->address();
      dip4_ = dst->ipv4()->address();
    } else if (src && dst && src->ipv6() && dst->ipv6()) {
      family_ = AF_INET6;
      sip6_ = src->ipv6()->address();
      dip6_ = dst->ipv6()->address();
    } else {
      throw EnvoyException("mux_socket: Invalid address families");
    }
    sport_ = htons(src->port());
    dport_ = htons(dst->port());
  }

  ShimTuple(const void *mem) {
    memcpy(this, mem, sizeof(*this));
  }

  ShimTuple(uint8_t family, absl::uint128 src, absl::uint128 dst, uint32_t sport, uint32_t dport) {
    memset(this, 0, sizeof(*this));
    sip6_ = src;
    dip6_ = dst;
    family_ = family;
    sport_ = sport;
    dport_ = dport;
  }

  // Flip the source and destination addresses and ports
  ShimTuple operator~() const {
    return ShimTuple(family_, dip6_, sip6_, dport_, sport_);
  }
  
  bool operator==(const ShimTuple& other) const {
    return memcmp(this, &other, sizeof *this) == 0;
  }

  bool srcMatch(const Network::Address::Ip* ip) const {
    return sport_ == htons(ip->port()) &&
      ((family_ == AF_INET && ip->ipv4() && sip4_ == ip->ipv4()->address()) ||
       (family_ == AF_INET6 && ip->ipv6() && sip6_ == ip->ipv6()->address()));
  }

  bool dstMatch(const Network::Address::Ip* ip) const {
    return dport_ == htons(ip->port()) &&
      ((family_ == AF_INET && ip->ipv4() && dip4_ == ip->ipv4()->address()) ||
       (family_ == AF_INET6 && ip->ipv6() && dip6_ == ip->ipv6()->address()));
  }

  operator std::vector<uint32_t>() const {
    std::vector<uint32_t> key(reinterpret_cast<const uint32_t*>(this), &dport_ + 1);
    return key;
  }

  Network::Address::InstanceConstSharedPtr srcAddress() const {
    union {
      struct sockaddr_in6 sin6{};
      struct sockaddr_in sin;
      struct sockaddr_storage ss;
    };
    size_t ss_size;

    ss.ss_family = family_;
    if (family_ == AF_INET6) {
      memcpy(static_cast<void*>(&sin6.sin6_addr.s6_addr), static_cast<const void*>(&dip6_), sizeof(sip6_));
      sin6.sin6_port = sport_;
      ss_size = sizeof(sin6);
    } else {
      ASSERT(family_ == AF_INET);
      sin.sin_addr.s_addr = sip4_;
      sin.sin_port = sport_;
      ss_size = sizeof(sin);
    }
    return Network::Address::addressFromSockAddr(ss, ss_size, false);
  }

  Network::Address::InstanceConstSharedPtr dstAddress() const {
    union {
      struct sockaddr_in6 sin6{};
      struct sockaddr_in sin;
      struct sockaddr_storage ss;
    };
    size_t ss_size;

    ss.ss_family = family_;
    if (family_ == AF_INET6) {
      memcpy(static_cast<void*>(&sin6.sin6_addr.s6_addr), static_cast<const void*>(&dip6_), sizeof(dip6_));
      sin6.sin6_port = dport_;
      ss_size = sizeof(sin6);
    } else {
      ASSERT(family_ == AF_INET);
      sin.sin_addr.s_addr = dip4_;
      sin.sin_port = dport_;
      ss_size = sizeof(sin);
    }
    return Network::Address::addressFromSockAddr(ss, ss_size, false);
  }
  
  union {
    uint32_t sip4_;
    absl::uint128 sip6_;
  };
  union {
    uint32_t dip4_;
    absl::uint128 dip6_;
  };
  uint8_t  family_;
  uint8_t  pad1_;
  uint16_t pad2_;
  uint32_t sport_;
  uint32_t dport_; // must be last
};

struct ShimHeader {
#if 1
  ShimTuple id_;
  uint32_t length_; // frame length, NOT including this shim header

  ShimHeader(const ShimTuple& id, uint32_t length) : id_(id), length_(length) {}
  ShimHeader(Buffer::Instance& buffer) : id_(buffer.linearize(sizeof *this)) {
    buffer.copyOut(sizeof id_, sizeof length_, &length_);
    buffer.drain(sizeof(*this));
  }
  
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
