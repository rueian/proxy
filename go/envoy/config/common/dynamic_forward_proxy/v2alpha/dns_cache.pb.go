// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/config/common/dynamic_forward_proxy/v2alpha/dns_cache.proto

package envoy_config_common_dynamic_forward_proxy_v2alpha

import (
	fmt "fmt"
	v2 "github.com/cilium/proxy/go/envoy/api/v2"
	_ "github.com/cncf/udpa/go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	duration "github.com/golang/protobuf/ptypes/duration"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Configuration for the dynamic forward proxy DNS cache. See the :ref:`architecture overview
// <arch_overview_http_dynamic_forward_proxy>` for more information.
// [#next-free-field: 7]
type DnsCacheConfig struct {
	// The name of the cache. Multiple named caches allow independent dynamic forward proxy
	// configurations to operate within a single Envoy process using different configurations. All
	// configurations with the same name *must* otherwise have the same settings when referenced
	// from different configuration components. Configuration will fail to load if this is not
	// the case.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// The DNS lookup family to use during resolution.
	//
	// [#comment:TODO(mattklein123): Figure out how to support IPv4/IPv6 "happy eyeballs" mode. The
	// way this might work is a new lookup family which returns both IPv4 and IPv6 addresses, and
	// then configures a host to have a primary and fall back address. With this, we could very
	// likely build a "happy eyeballs" connection pool which would race the primary / fall back
	// address and return the one that wins. This same method could potentially also be used for
	// QUIC to TCP fall back.]
	DnsLookupFamily v2.Cluster_DnsLookupFamily `protobuf:"varint,2,opt,name=dns_lookup_family,json=dnsLookupFamily,proto3,enum=envoy.api.v2.Cluster_DnsLookupFamily" json:"dns_lookup_family,omitempty"`
	// The DNS refresh rate for currently cached DNS hosts. If not specified defaults to 60s.
	//
	// .. note:
	//
	//  The returned DNS TTL is not currently used to alter the refresh rate. This feature will be
	//  added in a future change.
	//
	// .. note:
	//
	// The refresh rate is rounded to the closest millisecond, and must be at least 1ms.
	DnsRefreshRate *duration.Duration `protobuf:"bytes,3,opt,name=dns_refresh_rate,json=dnsRefreshRate,proto3" json:"dns_refresh_rate,omitempty"`
	// The TTL for hosts that are unused. Hosts that have not been used in the configured time
	// interval will be purged. If not specified defaults to 5m.
	//
	// .. note:
	//
	//   The TTL is only checked at the time of DNS refresh, as specified by *dns_refresh_rate*. This
	//   means that if the configured TTL is shorter than the refresh rate the host may not be removed
	//   immediately.
	//
	//  .. note:
	//
	//   The TTL has no relation to DNS TTL and is only used to control Envoy's resource usage.
	HostTtl *duration.Duration `protobuf:"bytes,4,opt,name=host_ttl,json=hostTtl,proto3" json:"host_ttl,omitempty"`
	// The maximum number of hosts that the cache will hold. If not specified defaults to 1024.
	//
	// .. note:
	//
	//   The implementation is approximate and enforced independently on each worker thread, thus
	//   it is possible for the maximum hosts in the cache to go slightly above the configured
	//   value depending on timing. This is similar to how other circuit breakers work.
	MaxHosts *wrappers.UInt32Value `protobuf:"bytes,5,opt,name=max_hosts,json=maxHosts,proto3" json:"max_hosts,omitempty"`
	// If the DNS failure refresh rate is specified,
	// this is used as the cache's DNS refresh rate when DNS requests are failing. If this setting is
	// not specified, the failure refresh rate defaults to the dns_refresh_rate.
	DnsFailureRefreshRate *v2.Cluster_RefreshRate `protobuf:"bytes,6,opt,name=dns_failure_refresh_rate,json=dnsFailureRefreshRate,proto3" json:"dns_failure_refresh_rate,omitempty"`
	XXX_NoUnkeyedLiteral  struct{}                `json:"-"`
	XXX_unrecognized      []byte                  `json:"-"`
	XXX_sizecache         int32                   `json:"-"`
}

func (m *DnsCacheConfig) Reset()         { *m = DnsCacheConfig{} }
func (m *DnsCacheConfig) String() string { return proto.CompactTextString(m) }
func (*DnsCacheConfig) ProtoMessage()    {}
func (*DnsCacheConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_d2d9297e0c94cb56, []int{0}
}

func (m *DnsCacheConfig) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DnsCacheConfig.Unmarshal(m, b)
}
func (m *DnsCacheConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DnsCacheConfig.Marshal(b, m, deterministic)
}
func (m *DnsCacheConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DnsCacheConfig.Merge(m, src)
}
func (m *DnsCacheConfig) XXX_Size() int {
	return xxx_messageInfo_DnsCacheConfig.Size(m)
}
func (m *DnsCacheConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_DnsCacheConfig.DiscardUnknown(m)
}

var xxx_messageInfo_DnsCacheConfig proto.InternalMessageInfo

func (m *DnsCacheConfig) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *DnsCacheConfig) GetDnsLookupFamily() v2.Cluster_DnsLookupFamily {
	if m != nil {
		return m.DnsLookupFamily
	}
	return v2.Cluster_AUTO
}

func (m *DnsCacheConfig) GetDnsRefreshRate() *duration.Duration {
	if m != nil {
		return m.DnsRefreshRate
	}
	return nil
}

func (m *DnsCacheConfig) GetHostTtl() *duration.Duration {
	if m != nil {
		return m.HostTtl
	}
	return nil
}

func (m *DnsCacheConfig) GetMaxHosts() *wrappers.UInt32Value {
	if m != nil {
		return m.MaxHosts
	}
	return nil
}

func (m *DnsCacheConfig) GetDnsFailureRefreshRate() *v2.Cluster_RefreshRate {
	if m != nil {
		return m.DnsFailureRefreshRate
	}
	return nil
}

func init() {
	proto.RegisterType((*DnsCacheConfig)(nil), "envoy.config.common.dynamic_forward_proxy.v2alpha.DnsCacheConfig")
}

func init() {
	proto.RegisterFile("envoy/config/common/dynamic_forward_proxy/v2alpha/dns_cache.proto", fileDescriptor_d2d9297e0c94cb56)
}

var fileDescriptor_d2d9297e0c94cb56 = []byte{
	// 515 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x92, 0x4f, 0x8b, 0x13, 0x31,
	0x18, 0xc6, 0x37, 0xb3, 0x6d, 0xb7, 0x1d, 0xb5, 0xd6, 0x01, 0x71, 0xac, 0x7f, 0xa8, 0x82, 0x50,
	0xf6, 0x90, 0xe8, 0xf4, 0xac, 0xe2, 0xb4, 0x2c, 0x0a, 0x1e, 0xd6, 0x41, 0x3d, 0xe8, 0x61, 0x78,
	0x77, 0x26, 0xd3, 0x0e, 0xce, 0x24, 0x43, 0x92, 0xe9, 0xb6, 0x37, 0x11, 0xef, 0x82, 0x27, 0x3f,
	0xc3, 0x7e, 0x04, 0x41, 0xf0, 0xe8, 0xd5, 0xaf, 0xe2, 0xb1, 0x07, 0x91, 0x24, 0x2d, 0xec, 0xb2,
	0x2b, 0xcb, 0xde, 0x92, 0x3c, 0x79, 0x7e, 0xc9, 0xf3, 0xf0, 0xba, 0xcf, 0x28, 0x9b, 0xf3, 0x25,
	0x49, 0x38, 0xcb, 0xf2, 0x29, 0x49, 0x78, 0x59, 0x72, 0x46, 0xd2, 0x25, 0x83, 0x32, 0x4f, 0xe2,
	0x8c, 0x8b, 0x43, 0x10, 0x69, 0x5c, 0x09, 0xbe, 0x58, 0x92, 0x79, 0x00, 0x45, 0x35, 0x03, 0x92,
	0x32, 0x19, 0x27, 0x90, 0xcc, 0x28, 0xae, 0x04, 0x57, 0xdc, 0x7b, 0x64, 0x10, 0xd8, 0x22, 0xb0,
	0x45, 0xe0, 0x33, 0x11, 0x78, 0x8d, 0xe8, 0xf7, 0xed, 0xab, 0x50, 0xe5, 0x64, 0x1e, 0x90, 0xa4,
	0xa8, 0xa5, 0xa2, 0xc2, 0xe2, 0xfa, 0x77, 0xa7, 0x9c, 0x4f, 0x0b, 0x4a, 0xcc, 0xee, 0xa0, 0xce,
	0x48, 0x5a, 0x0b, 0x50, 0x39, 0x67, 0xff, 0xd3, 0x0f, 0x05, 0x54, 0x15, 0x15, 0x72, 0xa3, 0xd7,
	0x69, 0x05, 0x04, 0x18, 0xe3, 0xca, 0xd8, 0x24, 0x29, 0xf3, 0xa9, 0x00, 0xb5, 0xfe, 0x6e, 0xff,
	0xce, 0x29, 0x5d, 0x2a, 0x50, 0xf5, 0xc6, 0x7e, 0x63, 0x0e, 0x45, 0x9e, 0x82, 0xa2, 0x64, 0xb3,
	0xb0, 0xc2, 0xfd, 0x1f, 0xdb, 0x6e, 0x77, 0xc2, 0xe4, 0x58, 0x27, 0x1f, 0x9b, 0xac, 0xde, 0x2d,
	0xb7, 0xc1, 0xa0, 0xa4, 0x3e, 0x1a, 0xa0, 0x61, 0x27, 0xdc, 0x59, 0x85, 0x0d, 0xe1, 0x0c, 0x50,
	0x64, 0x0e, 0xbd, 0xf7, 0xee, 0x35, 0xdd, 0x54, 0xc1, 0xf9, 0x87, 0xba, 0x8a, 0x33, 0x28, 0xf3,
	0x62, 0xe9, 0x3b, 0x03, 0x34, 0xec, 0x06, 0x0f, 0xb0, 0xad, 0x0c, 0xaa, 0x1c, 0xcf, 0x03, 0x3c,
	0x5e, 0xe7, 0x9f, 0x30, 0xf9, 0xd2, 0xdc, 0xde, 0x33, 0x97, 0xc3, 0xf6, 0x2a, 0x6c, 0x7e, 0x42,
	0x4e, 0x0f, 0x45, 0x57, 0xd3, 0x93, 0x92, 0xf7, 0xca, 0xed, 0x69, 0xb8, 0xa0, 0x99, 0xa0, 0x72,
	0x16, 0xeb, 0x78, 0xfe, 0xf6, 0x00, 0x0d, 0x2f, 0x05, 0x37, 0xb1, 0xed, 0x07, 0x6f, 0xfa, 0xc1,
	0x93, 0x75, 0x7f, 0xe1, 0xe5, 0x55, 0xd8, 0x39, 0x42, 0xad, 0xa0, 0xd1, 0xfb, 0xf9, 0xf9, 0x71,
	0xd4, 0x4d, 0x99, 0x8c, 0xac, 0x3f, 0x02, 0x45, 0xbd, 0x27, 0x6e, 0x7b, 0xc6, 0xa5, 0x8a, 0x95,
	0x2a, 0xfc, 0xc6, 0x79, 0x28, 0xfd, 0xb5, 0x23, 0xe4, 0xec, 0x6e, 0x45, 0x3b, 0xda, 0xf4, 0x5a,
	0x15, 0x5e, 0xe8, 0x76, 0x4a, 0x58, 0xc4, 0x7a, 0x2b, 0xfd, 0xa6, 0x01, 0xdc, 0x3e, 0x05, 0x78,
	0xf3, 0x82, 0xa9, 0x51, 0xf0, 0x16, 0x8a, 0x9a, 0x9a, 0xbe, 0x76, 0x9d, 0xc1, 0x56, 0xd4, 0x2e,
	0x61, 0xf1, 0x5c, 0xdb, 0xbc, 0x77, 0xae, 0xaf, 0x63, 0x65, 0x90, 0x17, 0xb5, 0xa0, 0x27, 0xe3,
	0xb5, 0x0c, 0xf2, 0xde, 0xd9, 0xd5, 0x1d, 0x0b, 0x12, 0x5d, 0x4f, 0x99, 0xdc, 0xb3, 0x84, 0x63,
	0xc7, 0xe1, 0x57, 0xf4, 0xe7, 0xdb, 0xdf, 0x2f, 0xcd, 0xc0, 0x7b, 0x68, 0x09, 0x74, 0xa1, 0x28,
	0x93, 0x7a, 0x00, 0xce, 0x99, 0xd9, 0xd1, 0xf7, 0x8f, 0xbf, 0x7e, 0xb7, 0x9c, 0x1e, 0x72, 0x9f,
	0xe6, 0xdc, 0x3e, 0x6f, 0x95, 0x0b, 0xcf, 0x7d, 0x78, 0x65, 0x33, 0x40, 0xfb, 0xba, 0x90, 0x7d,
	0x74, 0xd0, 0x32, 0xcd, 0x8c, 0xfe, 0x05, 0x00, 0x00, 0xff, 0xff, 0xed, 0x8c, 0x7e, 0xe3, 0x87,
	0x03, 0x00, 0x00,
}
