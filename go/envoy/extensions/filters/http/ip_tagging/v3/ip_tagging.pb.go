// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/extensions/filters/http/ip_tagging/v3/ip_tagging.proto

package envoy_extensions_filters_http_ip_tagging_v3

import (
	fmt "fmt"
	v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	_ "github.com/cncf/udpa/go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
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

// The type of requests the filter should apply to. The supported types
// are internal, external or both. The
// :ref:`x-forwarded-for<config_http_conn_man_headers_x-forwarded-for_internal_origin>` header is
// used to determine if a request is internal and will result in
// :ref:`x-envoy-internal<config_http_conn_man_headers_x-envoy-internal>`
// being set. The filter defaults to both, and it will apply to all request types.
type IPTagging_RequestType int32

const (
	// Both external and internal requests will be tagged. This is the default value.
	IPTagging_BOTH IPTagging_RequestType = 0
	// Only internal requests will be tagged.
	IPTagging_INTERNAL IPTagging_RequestType = 1
	// Only external requests will be tagged.
	IPTagging_EXTERNAL IPTagging_RequestType = 2
)

var IPTagging_RequestType_name = map[int32]string{
	0: "BOTH",
	1: "INTERNAL",
	2: "EXTERNAL",
}

var IPTagging_RequestType_value = map[string]int32{
	"BOTH":     0,
	"INTERNAL": 1,
	"EXTERNAL": 2,
}

func (x IPTagging_RequestType) String() string {
	return proto.EnumName(IPTagging_RequestType_name, int32(x))
}

func (IPTagging_RequestType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_53ea551b2829685a, []int{0, 0}
}

type IPTagging struct {
	// The type of request the filter should apply to.
	RequestType IPTagging_RequestType `protobuf:"varint,1,opt,name=request_type,json=requestType,proto3,enum=envoy.extensions.filters.http.ip_tagging.v3.IPTagging_RequestType" json:"request_type,omitempty"`
	// [#comment:TODO(ccaraman): Extend functionality to load IP tags from file system.
	// Tracked by issue https://github.com/envoyproxy/envoy/issues/2695]
	// The set of IP tags for the filter.
	IpTags               []*IPTagging_IPTag `protobuf:"bytes,4,rep,name=ip_tags,json=ipTags,proto3" json:"ip_tags,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *IPTagging) Reset()         { *m = IPTagging{} }
func (m *IPTagging) String() string { return proto.CompactTextString(m) }
func (*IPTagging) ProtoMessage()    {}
func (*IPTagging) Descriptor() ([]byte, []int) {
	return fileDescriptor_53ea551b2829685a, []int{0}
}

func (m *IPTagging) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IPTagging.Unmarshal(m, b)
}
func (m *IPTagging) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IPTagging.Marshal(b, m, deterministic)
}
func (m *IPTagging) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IPTagging.Merge(m, src)
}
func (m *IPTagging) XXX_Size() int {
	return xxx_messageInfo_IPTagging.Size(m)
}
func (m *IPTagging) XXX_DiscardUnknown() {
	xxx_messageInfo_IPTagging.DiscardUnknown(m)
}

var xxx_messageInfo_IPTagging proto.InternalMessageInfo

func (m *IPTagging) GetRequestType() IPTagging_RequestType {
	if m != nil {
		return m.RequestType
	}
	return IPTagging_BOTH
}

func (m *IPTagging) GetIpTags() []*IPTagging_IPTag {
	if m != nil {
		return m.IpTags
	}
	return nil
}

// Supplies the IP tag name and the IP address subnets.
type IPTagging_IPTag struct {
	// Specifies the IP tag name to apply.
	IpTagName string `protobuf:"bytes,1,opt,name=ip_tag_name,json=ipTagName,proto3" json:"ip_tag_name,omitempty"`
	// A list of IP address subnets that will be tagged with
	// ip_tag_name. Both IPv4 and IPv6 are supported.
	IpList               []*v3.CidrRange `protobuf:"bytes,2,rep,name=ip_list,json=ipList,proto3" json:"ip_list,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *IPTagging_IPTag) Reset()         { *m = IPTagging_IPTag{} }
func (m *IPTagging_IPTag) String() string { return proto.CompactTextString(m) }
func (*IPTagging_IPTag) ProtoMessage()    {}
func (*IPTagging_IPTag) Descriptor() ([]byte, []int) {
	return fileDescriptor_53ea551b2829685a, []int{0, 0}
}

func (m *IPTagging_IPTag) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IPTagging_IPTag.Unmarshal(m, b)
}
func (m *IPTagging_IPTag) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IPTagging_IPTag.Marshal(b, m, deterministic)
}
func (m *IPTagging_IPTag) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IPTagging_IPTag.Merge(m, src)
}
func (m *IPTagging_IPTag) XXX_Size() int {
	return xxx_messageInfo_IPTagging_IPTag.Size(m)
}
func (m *IPTagging_IPTag) XXX_DiscardUnknown() {
	xxx_messageInfo_IPTagging_IPTag.DiscardUnknown(m)
}

var xxx_messageInfo_IPTagging_IPTag proto.InternalMessageInfo

func (m *IPTagging_IPTag) GetIpTagName() string {
	if m != nil {
		return m.IpTagName
	}
	return ""
}

func (m *IPTagging_IPTag) GetIpList() []*v3.CidrRange {
	if m != nil {
		return m.IpList
	}
	return nil
}

func init() {
	proto.RegisterEnum("envoy.extensions.filters.http.ip_tagging.v3.IPTagging_RequestType", IPTagging_RequestType_name, IPTagging_RequestType_value)
	proto.RegisterType((*IPTagging)(nil), "envoy.extensions.filters.http.ip_tagging.v3.IPTagging")
	proto.RegisterType((*IPTagging_IPTag)(nil), "envoy.extensions.filters.http.ip_tagging.v3.IPTagging.IPTag")
}

func init() {
	proto.RegisterFile("envoy/extensions/filters/http/ip_tagging/v3/ip_tagging.proto", fileDescriptor_53ea551b2829685a)
}

var fileDescriptor_53ea551b2829685a = []byte{
	// 435 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x92, 0x41, 0x6b, 0x14, 0x31,
	0x14, 0xc7, 0xcd, 0xb4, 0x5d, 0x77, 0x33, 0xa5, 0x0c, 0x73, 0x71, 0x19, 0xb0, 0xd6, 0x3d, 0x15,
	0x84, 0x44, 0x66, 0x40, 0x6b, 0xa9, 0x07, 0x47, 0x0a, 0x2e, 0x94, 0x75, 0x19, 0x46, 0xf0, 0x36,
	0xc4, 0x4e, 0x3a, 0x06, 0xb6, 0x49, 0x4c, 0xb2, 0x43, 0xe7, 0x26, 0x9e, 0x3c, 0x7b, 0xf4, 0xe4,
	0xe7, 0xf0, 0x2e, 0x78, 0xf5, 0x8b, 0xf8, 0x01, 0x3c, 0x49, 0x92, 0x69, 0xbb, 0xda, 0xd3, 0xf6,
	0x36, 0x6f, 0xde, 0xfb, 0xff, 0xff, 0xbf, 0x97, 0x04, 0x1e, 0x51, 0xde, 0x8a, 0x0e, 0xd3, 0x0b,
	0x43, 0xb9, 0x66, 0x82, 0x6b, 0x7c, 0xc6, 0x16, 0x86, 0x2a, 0x8d, 0xdf, 0x1b, 0x23, 0x31, 0x93,
	0x95, 0x21, 0x4d, 0xc3, 0x78, 0x83, 0xdb, 0x6c, 0xa5, 0x42, 0x52, 0x09, 0x23, 0xe2, 0x47, 0x4e,
	0x8d, 0xae, 0xd5, 0xa8, 0x57, 0x23, 0xab, 0x46, 0x2b, 0xf3, 0x6d, 0x96, 0x4c, 0x7c, 0xd4, 0xa9,
	0xe0, 0x67, 0xac, 0xc1, 0xa7, 0x42, 0x51, 0xeb, 0x49, 0xea, 0x5a, 0x51, 0xad, 0xbd, 0x61, 0x72,
	0x7f, 0x59, 0x4b, 0x82, 0x09, 0xe7, 0xc2, 0x10, 0xe3, 0x70, 0xb4, 0x21, 0x66, 0x79, 0xd9, 0x7e,
	0x78, 0xa3, 0xdd, 0x52, 0x65, 0x83, 0xaf, 0x90, 0x92, 0x7b, 0x2d, 0x59, 0xb0, 0x9a, 0x18, 0x8a,
	0x2f, 0x3f, 0x7c, 0x63, 0xf2, 0x7b, 0x03, 0x8e, 0xa6, 0xf3, 0xd2, 0xf3, 0xc4, 0x02, 0x6e, 0x2b,
	0xfa, 0x61, 0x49, 0xb5, 0xa9, 0x4c, 0x27, 0xe9, 0x18, 0xec, 0x81, 0xfd, 0x9d, 0x34, 0x47, 0x6b,
	0x2c, 0x84, 0xae, 0xdc, 0x50, 0xe1, 0xad, 0xca, 0x4e, 0xd2, 0x7c, 0xf8, 0x27, 0xdf, 0xfa, 0x04,
	0x82, 0x08, 0x14, 0xa1, 0xba, 0xfe, 0x1d, 0x57, 0xf0, 0xae, 0x57, 0xeb, 0xf1, 0xe6, 0xde, 0xc6,
	0x7e, 0x98, 0x1e, 0xdd, 0x32, 0xcb, 0x7d, 0xb9, 0x94, 0x2f, 0x20, 0x18, 0x82, 0x62, 0xc0, 0x64,
	0x49, 0x1a, 0x9d, 0x7c, 0x03, 0x70, 0xcb, 0xf5, 0xe2, 0x5d, 0x18, 0x7a, 0x71, 0xc5, 0xc9, 0xb9,
	0x5f, 0x6d, 0x54, 0x8c, 0xdc, 0xd8, 0x8c, 0x9c, 0xd3, 0xf8, 0xc0, 0xa1, 0x2c, 0x98, 0x36, 0xe3,
	0xc0, 0xa1, 0x3c, 0xe8, 0x51, 0xfc, 0xd5, 0x20, 0x7b, 0x35, 0x36, 0xf3, 0x25, 0xab, 0x55, 0x41,
	0x78, 0x43, 0x6d, 0xc6, 0x09, 0xd3, 0xe6, 0xf0, 0xf9, 0xd7, 0x1f, 0x9f, 0x77, 0x0f, 0xe0, 0x93,
	0x7f, 0xc6, 0x3d, 0xf5, 0x4d, 0xe8, 0xf4, 0x7f, 0xe8, 0x49, 0x06, 0xc3, 0x95, 0x93, 0x8a, 0x87,
	0x70, 0x33, 0x7f, 0x5d, 0xbe, 0x8a, 0xee, 0xc4, 0xdb, 0x70, 0x38, 0x9d, 0x95, 0xc7, 0xc5, 0xec,
	0xc5, 0x49, 0x04, 0x6c, 0x75, 0xfc, 0xb6, 0xaf, 0x82, 0xc3, 0xa7, 0x36, 0x33, 0x85, 0x8f, 0xd7,
	0xcd, 0xcc, 0xdf, 0x7c, 0xff, 0xf8, 0xf3, 0xd7, 0x20, 0x88, 0x02, 0xf8, 0x8c, 0x09, 0xbf, 0xa1,
	0x54, 0xe2, 0xa2, 0x5b, 0xe7, 0xdc, 0xf3, 0x9d, 0xa9, 0xec, 0xfd, 0xe6, 0xf6, 0x15, 0xcd, 0xc1,
	0xbb, 0x81, 0x7b, 0x4e, 0xd9, 0xdf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x80, 0xca, 0x4d, 0x96, 0x3a,
	0x03, 0x00, 0x00,
}
