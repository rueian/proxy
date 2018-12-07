#include "mux_socket.h"

#include "common/common/assert.h"
#include "common/common/empty_string.h"
#include "common/network/listen_socket_impl.h"
#include "envoy/registry/registry.h"

namespace Envoy {
namespace Cilium {
  
std::string MuxSocketName("cilium.transport_sockets.mux");

typedef std::function<void()> ReadCB;
typedef std::function<void()> DeleteCB;

// Data for a mux keyed by the fd
// Not sure yet if access from multiple threads is actually needed
class MuxData {
public:
  // Caller has cleared 'id.length_'!
  MuxData(Mux& mux, const ShimHeader& id, int fd, bool upstream) : mux_(mux), id_(id), fd_(fd), upstream_(upstream) {}
  ~MuxData() {
    if (deleteCallback_) {
      deleteCallback_();
    }
  }

  void setCallbacks(ReadCB cb, DeleteCB delCb) {
    ENVOY_LOG_MISC(trace, "{}MUXT setting callbacks", upstream_ ? 'U' : 'D');
    readCallback_ = cb;
    deleteCallback_ = delCb;
  }

  Mux& mux_;
  const ShimHeader id_; // in the write order, reader side has the reverse key in Mux::buffers_. zero length_
  int fd_;
  bool upstream_;
  ReadCB readCallback_{};
  DeleteCB deleteCallback_{};

  mutable Thread::MutexBasicLockable lock_;
  Buffer::OwnedImpl read_buffer_ GUARDED_BY(lock_);  // Input frames ready to be read
  bool end_stream_{false} GUARDED_BY(lock_);
};

// Multiplexed read buffers by fd
static Thread::MutexBasicLockable mux_lock;
static std::map<int, MuxData*> muxed_buffers GUARDED_BY(mux_lock);

void MuxSocket::setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) {
  callbacks_ = &callbacks;
  ASSERT(mux_data_ == nullptr);

  if (!upstream_) {
    // Find mux_data_ based on the fd
    fd_ = callbacks_->fd();

    Thread::LockGuard guard(mux_lock);
    auto it = muxed_buffers.find(fd_);
    if (it != muxed_buffers.end()) {
      ENVOY_LOG_MISC(trace, "{}MUXT found muxed read buffer for fd {}", upstream_ ? 'U' : 'D', fd_);
      mux_data_ = it->second;
    } else {
      ENVOY_LOG_MISC(trace, "{}MUXT DID NOT find muxed read buffer for fd {}", upstream_ ? 'U' : 'D', fd_); 
    }
  } else {
    // Upstream: Find a mux based on the connection metadata and dup and reset the
    // upstream Mux fd.
    auto ip = callbacks_->connection().remoteAddress()->ip();
    auto ip_src = callbacks_->connection().localAddress()->ip();
    ENVOY_LOG_MISC(trace, "{}MUXT local address {}", upstream_ ? 'U' : 'D',
		   callbacks_->connection().localAddress()->asString()); 
    mux_lock.lock();

    for (auto it = muxed_buffers.begin(); it != muxed_buffers.end(); it++) {
      MuxData* mux_data = it->second;
      // Downstream 'id_' is in the writer order, it's source address is the upstream remote address!
      // XXX Match also the source (local) address, and make sure it is not nullptr
      if (mux_data->id_.srcMatch(ip) && mux_data->id_.dstMatch(ip_src)) {
	ENVOY_LOG_MISC(trace, "{}MUXT found corresponding downstream connection on fd {} on mux {}!", upstream_ ? 'U' : 'D', it->first, static_cast<void*>(&mux_data->mux_));
	// Create an upstream Mux for testing purposes if not already created
	auto upstream_mux = mux_data->mux_.other_;
	if (upstream_mux != nullptr) {
	  mux_lock.unlock();
	  {
	    Thread::LockGuard guard(upstream_mux->lock_);
	    mux_data_ = upstream_mux->addBuffer(mux_data->id_, true);
	  }
	  callbacks_->socket().resetFd(mux_data_->fd_);
	  fd_ = callbacks_->fd();
	  break;
	}
	ENVOY_LOG_MISC(trace, "{}MUXT UPSTREAM MUX NOT FOUND!", upstream_ ? 'U' : 'D');
      }
    }
    if (mux_data_ == nullptr) {
      mux_lock.unlock();
    }	  
  }
  if (mux_data_ != nullptr) {
    mux_data_->setCallbacks([this]() {
	ENVOY_LOG_MISC(trace, "{}MUXT SETTING read buffer ready", upstream_ ? 'U' : 'D');
	callbacks_->setReadBufferReady();
      },
      [this]() {
	ENVOY_LOG_MISC(trace, "{}MUXT ERASED", upstream_ ? 'U' : 'D');
	mux_data_ = nullptr;
      });
  }
}

void MuxSocket::closeSocket(Network::ConnectionEvent event) {
  ENVOY_LOG_MISC(trace, "MuxSocket::closeSocket({})", int(event));
  if (event == Network::ConnectionEvent::RemoteClose) {
    if (mux_data_ != nullptr) {
      mux_data_->mux_.removeBuffer(fd_);
      mux_data_ = nullptr;
    }
  }
}

MuxSocket::~MuxSocket() {
  closeSocket(Network::ConnectionEvent::RemoteClose);
}

Network::IoResult MuxSocket::doRead(Buffer::Instance& buffer) {
  if (mux_data_ == nullptr) {
    ENVOY_LOG_MISC(trace, "No {}MUXT data!", upstream_ ? 'U' : 'D');
    return {Network::PostIoAction::Close, 0, true};
  }

  // Kick the mux transport to read data
  mux_data_->mux_.readAndDemux(upstream_);

  // Move all available data to the caller's buffer
  mux_data_->lock_.lock();
  bool end_stream = mux_data_->end_stream_;
  uint64_t bytes_read = mux_data_->read_buffer_.length();
  buffer.move(mux_data_->read_buffer_);
  mux_data_->lock_.unlock();

  ENVOY_LOG_MISC(trace, "[{}] MUXT doRead read {} bytes", callbacks_->connection().id(), bytes_read);

  if (callbacks_->shouldDrainReadBuffer()) {
    ENVOY_LOG_MISC(trace, "[{}] MUXT doRead calling setReadBufferReady()", callbacks_->connection().id());
    callbacks_->setReadBufferReady();
  }

  return {Network::PostIoAction::KeepOpen, bytes_read, end_stream};
}

Network::IoResult MuxSocket::doWrite(Buffer::Instance& buffer, bool end_stream) {
  if (mux_data_ == nullptr) {
    ENVOY_LOG_MISC(trace, "No {}MUXT data!", upstream_ ? 'U' : 'D');
    return {Network::PostIoAction::Close, 0, false};
  }

  Network::PostIoAction action;
  uint64_t bytes_written = 0;
  ASSERT(!shutdown_ || buffer.length() == 0);
  do {
    if (buffer.length() == 0) {
      if (end_stream && !shutdown_) {
	ENVOY_CONN_LOG(trace, "{}MuxSocket write shutting down fd: {}", callbacks_->connection(), upstream_ ? 'U' : 'D', fd_);
        // Ignore the result. This can only fail if the connection failed. In that case, the
        // error will be detected on the next read, and dealt with appropriately.
	mux_data_->mux_.prependAndWrite(mux_data_->id_, buffer, mux_data_->fd_);
        shutdown_ = true;
      }
      action = Network::PostIoAction::KeepOpen;
      ENVOY_CONN_LOG(trace, "{}MuxSocket write skipped due to 0-length buffer (fd: {}, end_stream {})", callbacks_->connection(), upstream_ ? 'U' : 'D', fd_, end_stream ? "true" : "false");
      break;
    }
    Api::SysCallIntResult result = mux_data_->mux_.prependAndWrite(mux_data_->id_, buffer, mux_data_->fd_);
    ENVOY_CONN_LOG(trace, "{}MuxSocket write returns: {} (fd: {}, end_stream {})", callbacks_->connection(), upstream_ ? 'U' : 'D', result.rc_, fd_, end_stream ? "true" : "false");

    if (result.rc_ == -1) {
      ENVOY_CONN_LOG(trace, "write error: {} ({})", callbacks_->connection(), result.errno_,
                     strerror(result.errno_));
      if (result.errno_ == EAGAIN) {
        action = Network::PostIoAction::KeepOpen;
      } else {
        action = Network::PostIoAction::Close;
      }
      break;
    } else {
      bytes_written += result.rc_;
    }
  } while (true);

  return {action, bytes_written, false};
}

std::string MuxSocket::protocol() const { return MuxSocketName; } // XXX: HACK

void MuxSocket::onConnected() { callbacks_->raiseEvent(Network::ConnectionEvent::Connected); }

Mux::Mux(Event::Dispatcher& dispatcher, Network::ConnectionSocket& socket,
	 GetMetadataCB getMetadata, NewConnectionCB addNewConnetion, CloseMuxCB closeMux, bool upstream)
  : socket_(socket), getMetadata_(getMetadata), addNewConnection_(addNewConnetion), closeMux_(closeMux), upstream_(upstream) {
  file_event_ =
    dispatcher.createFileEvent(socket_.fd(),
			       [this](uint32_t events) {
				 if (events & Event::FileReadyType::Read) {
				   onRead();
				 }
				 if (events & Event::FileReadyType::Write) {
				   onWrite();
				 }
				 if (events & Event::FileReadyType::Closed) {
				   onClose();
				 }
			       },
			       Event::FileTriggerType::Edge,
			       Event::FileReadyType::Read |
			       Event::FileReadyType::Write |
			       Event::FileReadyType::Closed);

  timer_ = dispatcher.createTimer([this]() -> void { onTimeout(); });
  timer_->enableTimer(std::chrono::milliseconds(1));
}

Mux::~Mux() {
  ENVOY_LOG_MISC(trace, "{}MUX checking for buffers to clean up...", upstream_ ? 'U' : 'D');
  Thread::LockGuard guard(lock_);
  Thread::LockGuard mux_guard(mux_lock);
  for (auto it = muxed_buffers.begin(); it != muxed_buffers.end(); ) {
    MuxData* mux_data = it->second;
    if (&mux_data->mux_ == this) {
      ENVOY_LOG_MISC(trace, "{}MUX found buffer to clean up", upstream_ ? 'U' : 'D');
      removeBuffer_(mux_data);
    } else {
      it++;
    }
  }
  ASSERT(buffers_.empty());
}

void Mux::onRead() {
  ENVOY_LOG_MISC(trace, "{}MUXT test: onRead()", upstream_ ? 'U' : 'D');
  readAndDemux(upstream_);
}

void Mux::onWrite() {
  ENVOY_LOG_MISC(trace, "{}MUXT test: onWrite({})", upstream_ ? 'U' : 'D', write_buffer_.length());
  if (write_buffer_.length() > 0) {
    Api::SysCallIntResult result = write_buffer_.write(socket_.fd());
    ENVOY_LOG_MISC(trace, "{}MUX write returns: {}", upstream_ ? 'U' : 'D', result.rc_);
  }
}

void Mux::onTimeout() {
  ENVOY_LOG_MISC(trace, "{}MUX test: timeout", upstream_ ? 'U' : 'D');
  timer_.reset();
  readAndDemux(upstream_);
}

void Mux::onClose() {
  ENVOY_LOG_MISC(debug, "{}MUXT test: Closing socket", upstream_ ? 'U' : 'D');
  // Try flushing the data one more time
  onRead();
  onWrite();
  timer_.reset();
  file_event_.reset();
}

// called with 'lock_' held AND 'mux_lock' NOT held!
// caller has zeroed the length_ field of 'id'!
MuxData* Mux::addBuffer(const ShimHeader& id, bool upstream) {
  // Create a copy of the socket and pass it to addNewConnection callback.
  int fd2 = dup(socket_.fd());
  ASSERT(fd2 >= 0, "dup() failed");
  ENVOY_LOG_MISC(trace, "{}MUXT test: dupped fd {}", upstream_ ? 'U' : 'D', fd2);

  // 'buffers_' owns the MuxData objects!
  // MuxData 'id_' is in the writer order!

  // Remove any old buffer with the same key. This may happen if
  // Envoy retries on a multiplexed connection, as the new connection
  // will have the same 5-tuple.
  auto it = buffers_.find(id);
  if (it != buffers_.end()) {
    Thread::LockGuard mux_guard(mux_lock);
    removeBuffer_(it->second.get());
  }
  auto pair = buffers_.emplace(id, std::make_unique<MuxData>(*this, ~id, fd2, upstream));
  ASSERT(pair.second == true); // inserted
  ASSERT(pair.first != buffers_.end()); // inserted

  MuxData* mux_data = pair.first->second.get();
			       
  ENVOY_LOG_MISC(trace, "{}MUXT test: mux_data: {} ", upstream_ ? 'U' : 'D', static_cast<void*>(mux_data));

  // Add to the static index by fd as well
  {
    Thread::LockGuard mux_guard(mux_lock);
    muxed_buffers.emplace(fd2, mux_data);
  }

  ENVOY_LOG_MISC(trace, "{}MUXT test: after emplace of dupped fd {}", upstream_ ? 'U' : 'D', fd2);

  if (!upstream) {
    // Call the addNewConnection callback
    Network::ConnectionSocketPtr sock =
      std::make_unique<Network::ConnectionSocketImpl>(fd2, id.dstAddress(), id.srcAddress());
    ENVOY_LOG_MISC(trace, "{}MUXT test: ConnectionSocketImpl created on dupped fd {}, local {} remote {}", upstream_ ? 'U' : 'D', fd2, sock->localAddress()->asString(), sock->remoteAddress()->asString());

    getMetadata_(*sock);

    // Force the local address be marked as restored so that the original dst cluster will forward it
    sock->setLocalAddress(sock->localAddress(), true);
    ENVOY_LOG_MISC(trace, "{}MUXT test: Local address reset {} for fd {}, remote {} local {}", upstream_ ? 'U' : 'D', fd2, sock->remoteAddress()->asString(), sock->localAddress()->asString());
    sock->setDetectedTransportProtocol(MuxSocketName);

    ENVOY_LOG_MISC(trace, "{}MUXT test: newConnection on dupped fd {}", upstream_ ? 'U' : 'D', fd2);
    addNewConnection_(std::move(sock));
  } else {
    // Upstream connection
  }
  return mux_data;
}

// Locks already held
void Mux::removeBuffer_(MuxData* mux_data) {
  ENVOY_LOG_MISC(trace, "{}MUXT removeBuffer for fd: {}", upstream_ ? 'U' : 'D', mux_data->fd_);
  muxed_buffers.erase(mux_data->fd_);
  if (current_reader_ == mux_data) {
    current_reader_ = nullptr;
  }
  buffers_.erase(~mux_data->id_); // Frees the MuxData
}

// No locks held
void Mux::removeBuffer(int fd) {
  ENVOY_LOG_MISC(trace, "{}MUXT removeBuffer for fd: {}", upstream_ ? 'U' : 'D', fd);
  Thread::LockGuard guard(lock_);
  Thread::LockGuard mux_guard(mux_lock);
  auto it = muxed_buffers.find(fd);
  if (it != muxed_buffers.end()) {
    ENVOY_LOG_MISC(trace, "{}MUXT found buffer to delete", upstream_ ? 'U' : 'D');
    const auto* mux_data = it->second;
    muxed_buffers.erase(it); // invalidates 'it'
    if (current_reader_ == mux_data) {
      current_reader_ = nullptr;
    }
    buffers_.erase(~mux_data->id_); // Frees the MuxData
  }
}

void Mux::readAndDemux(bool upstream) {
  ASSERT(upstream == upstream_);
  Thread::LockGuard guard(lock_);
  do {
    // 16K read is arbitrary. TODO(mattklein123) PERF: Tune the read size.
    Api::SysCallIntResult result = read_buffer_.read(socket_.fd(), 16384);
    ENVOY_LOG_MISC(trace, "{}MUXT read returns: {}, read buffer length: {}", upstream_ ? 'U' : 'D', result.rc_, read_buffer_.length());

    if (result.rc_ == 0) {
      // Remote close.
      ENVOY_LOG_MISC(trace, "{}MUXT returned zero bytes, ending streams", upstream_ ? 'U' : 'D');
      for (auto it = buffers_.begin(); it != buffers_.end(); it++) {
	Thread::LockGuard buffer_guard(it->second->lock_);
	it->second->end_stream_ = true;
      }
      break;
    } else if (result.rc_ == -1) {
      // Remote error (might be no data).
      if (result.errno_ != EAGAIN) {
	ENVOY_LOG_MISC(trace, "{}MUXT read error: {}", upstream_ ? 'U' : 'D', result.errno_);
	for (auto it = buffers_.begin(); it != buffers_.end(); it++) {
	  Thread::LockGuard buffer_guard(it->second->lock_);
	  it->second->end_stream_ = true;
	}
	break;
      }
      break; // not now so that we can inject data for testing
    }
    // distribute the read bytes to demuxed read buffers
    do {
      // Are we in a middle of a partial frame?
      if (remaining_read_length_ > 0) {
	auto len = std::min(remaining_read_length_, read_buffer_.length());
	if (current_reader_ != nullptr) {
	  // Move input to the demuxed socket
	  Thread::LockGuard buffer_guard(current_reader_->lock_);
	  ENVOY_LOG_MISC(trace, "{}MUXT transfering {} bytes", upstream_ ? 'U' : 'D', len);
	  current_reader_->read_buffer_.move(read_buffer_, len);
	  // Wake the dupped fd (not sure if necessary)
	  if (current_reader_->readCallback_) {
	    current_reader_->readCallback_();
	  }
	} else {
	  // Demuxed socket has been closed before all input was received. Drain the bytes.
	  ENVOY_LOG_MISC(trace, "{}MUXT draining {} bytes", upstream_ ? 'U' : 'D', len);
	  read_buffer_.drain(len);
	}
	remaining_read_length_ -= len;
      }
      if (remaining_read_length_ == 0) {
	current_reader_ = nullptr;

	// Do we have enough data for the next shim header?
	if (read_buffer_.length() >= sizeof(ShimHeader)) {
	  ShimHeader hdr(read_buffer_);
	  remaining_read_length_ = hdr.length_ - sizeof hdr;
	  hdr.length_ = 0;
	  std::vector<uint32_t> key = hdr;

	  auto it = buffers_.find(key);
	  if (upstream_ && it == buffers_.end()) {
	    // upstream testing has a random source port and host address, match with the remote address only
	    auto ip_src = socket_.remoteAddress()->ip();
	    for (it = buffers_.begin(); it != buffers_.end(); it++) {
	      MuxData* mux_data = it->second.get();
	      // Upstream 'id_' is in the writer order, it's destination address is the upstream remote address!
	      // XXX Match also the source (local) address, and make sure it is not nullptr
	      if (mux_data->id_.dstMatch(ip_src)) {
		ENVOY_LOG_MISC(trace, "{}MUXT found THE upstream connection on fd {} on mux {}!", upstream_ ? 'U' : 'D', mux_data->fd_, static_cast<void*>(&mux_data->mux_));
		break;
	      }
	    }
	  }
	  if (it != buffers_.end()) {
	    if (remaining_read_length_ > 0 ) {
	      ENVOY_LOG_MISC(trace, "{}MUXT found buffer for frame length {}", upstream_ ? 'U' : 'D', remaining_read_length_);
	      current_reader_ = it->second.get();
	    } else {
	      ENVOY_LOG_MISC(trace, "{}MUXT found buffer, but closing for 0-length frame", upstream_ ? 'U' : 'D');
	      Thread::LockGuard buffer_guard(it->second->lock_);
	      it->second->end_stream_ = true;
	      // current_reader_ remoins nullptr
	    }
	  } else if (remaining_read_length_ > 0) {
	    // New connection?
	    ENVOY_LOG_MISC(trace, "{}MUXT did NOT find a buffer, creating a new one for frame length {}", upstream_ ? 'U' : 'D', remaining_read_length_);
	    current_reader_ = addBuffer(hdr, upstream_);
	  }
	}
      }
    } while (remaining_read_length_ > 0 && read_buffer_.length() > 0);
  } while (true);
}

Api::SysCallIntResult Mux::prependAndWrite(const ShimHeader& header, Buffer::Instance& buffer, int fd) {
  Thread::LockGuard guard(lock_);
  if (buffer.length() == 0) {
    return {0, 0};
  }

  uint32_t len = std::min(int(buffer.length()), 16384); // Limit for fearness?

  // Prepend a shim header for the data
#if 0
  write_buffer_.add(&header, sizeof header - sizeof(uint32_t));
  uint32_t write_len = len + sizeof header;
  write_buffer_.add(&write_len, sizeof(uint32_t));
#else
  auto write_header = header;
  write_header.length_ = len + sizeof write_header;  
  ENVOY_LOG_MISC(debug, "MUXT writing header: {}: {}, length: {}, size: {}", str(reinterpret_cast<const uint32_t*>(&write_header),
      reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(&write_header) + sizeof write_header)), write_header.String(), write_header.length_, sizeof write_header);
  write_buffer_.add(&write_header, sizeof write_header);
#endif
  write_buffer_.move(buffer, len);

  Api::SysCallIntResult result = write_buffer_.write(fd);
  ENVOY_LOG_MISC(trace, "MUXT write returns: {} ({})", result.rc_, strerror(result.errno_));

  if (result.rc_ == -1) {
    if (result.errno_ != EAGAIN) {
      ENVOY_LOG_MISC(trace, "write error: {} ({})", result.errno_, strerror(result.errno_));
    }
    return result;
  }
  return {int(len), 0};
}

Network::TransportSocketPtr MuxSocketFactory::createTransportSocket() const {
  return std::make_unique<MuxSocket>(upstream_);
}

bool MuxSocketFactory::implementsSecureTransport() const { return false; }

Network::TransportSocketFactoryPtr UpstreamMuxSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message&, Server::Configuration::TransportSocketFactoryContext&) {
  ENVOY_LOG_MISC(trace, "MUX created Upstream TransportSocketFactory");
  return std::make_unique<MuxSocketFactory>(true);
}

Network::TransportSocketFactoryPtr DownstreamMuxSocketConfigFactory::createTransportSocketFactory(
    const Protobuf::Message&, Server::Configuration::TransportSocketFactoryContext&,
    const std::vector<std::string>&) {
  ENVOY_LOG_MISC(trace, "MUX created Downstream TransportSocketFactory");
  return std::make_unique<MuxSocketFactory>(false);
}

ProtobufTypes::MessagePtr MuxSocketConfigFactory::createEmptyConfigProto() {
  return std::make_unique<ProtobufWkt::Empty>();
}

static Registry::RegisterFactory<UpstreamMuxSocketConfigFactory,
                                 Server::Configuration::UpstreamTransportSocketConfigFactory>
    upstream_registered_;

static Registry::RegisterFactory<DownstreamMuxSocketConfigFactory,
                                 Server::Configuration::DownstreamTransportSocketConfigFactory>
    downstream_registered_;

} // namespace Cilium
} // namespace Envoy
