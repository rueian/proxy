// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/data/cluster/v2alpha/outlier_detection_event.proto

package envoy_data_cluster_v2alpha

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/golang/protobuf/proto"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	_ "github.com/lyft/protoc-gen-validate/validate"
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

// Type of ejection that took place
type OutlierEjectionType int32

const (
	// In case upstream host returns certain number of consecutive 5xx
	OutlierEjectionType_CONSECUTIVE_5XX OutlierEjectionType = 0
	// In case upstream host returns certain number of consecutive gateway errors
	OutlierEjectionType_CONSECUTIVE_GATEWAY_FAILURE OutlierEjectionType = 1
	// Runs over aggregated success rate statistics from every host in cluster
	OutlierEjectionType_SUCCESS_RATE OutlierEjectionType = 2
)

var OutlierEjectionType_name = map[int32]string{
	0: "CONSECUTIVE_5XX",
	1: "CONSECUTIVE_GATEWAY_FAILURE",
	2: "SUCCESS_RATE",
}

var OutlierEjectionType_value = map[string]int32{
	"CONSECUTIVE_5XX":             0,
	"CONSECUTIVE_GATEWAY_FAILURE": 1,
	"SUCCESS_RATE":                2,
}

func (x OutlierEjectionType) String() string {
	return proto.EnumName(OutlierEjectionType_name, int32(x))
}

func (OutlierEjectionType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_5e03c92c55863094, []int{0}
}

// Represents possible action applied to upstream host
type Action int32

const (
	// In case host was excluded from service
	Action_EJECT Action = 0
	// In case host was brought back into service
	Action_UNEJECT Action = 1
)

var Action_name = map[int32]string{
	0: "EJECT",
	1: "UNEJECT",
}

var Action_value = map[string]int32{
	"EJECT":   0,
	"UNEJECT": 1,
}

func (x Action) String() string {
	return proto.EnumName(Action_name, int32(x))
}

func (Action) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_5e03c92c55863094, []int{1}
}

type OutlierDetectionEvent struct {
	// In case of eject represents type of ejection that took place.
	Type OutlierEjectionType `protobuf:"varint,1,opt,name=type,proto3,enum=envoy.data.cluster.v2alpha.OutlierEjectionType" json:"type,omitempty"`
	// Timestamp for event.
	Timestamp *timestamp.Timestamp `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// The time in seconds since the last action (either an ejection or unejection) took place.
	SecsSinceLastAction *wrappers.UInt64Value `protobuf:"bytes,3,opt,name=secs_since_last_action,json=secsSinceLastAction,proto3" json:"secs_since_last_action,omitempty"`
	// The :ref:`cluster <envoy_api_msg_Cluster>` that owns the ejected host.
	ClusterName string `protobuf:"bytes,4,opt,name=cluster_name,json=clusterName,proto3" json:"cluster_name,omitempty"`
	// The URL of the ejected host. E.g., ``tcp://1.2.3.4:80``.
	UpstreamUrl string `protobuf:"bytes,5,opt,name=upstream_url,json=upstreamUrl,proto3" json:"upstream_url,omitempty"`
	// The action that took place.
	Action Action `protobuf:"varint,6,opt,name=action,proto3,enum=envoy.data.cluster.v2alpha.Action" json:"action,omitempty"`
	// If ``action`` is ``eject``, specifies the number of times the host has been ejected (local to
	// that Envoy and gets reset if the host gets removed from the upstream cluster for any reason and
	// then re-added).
	NumEjections uint32 `protobuf:"varint,7,opt,name=num_ejections,json=numEjections,proto3" json:"num_ejections,omitempty"`
	// If ``action`` is ``eject``, specifies if the ejection was enforced. ``true`` means the host was
	// ejected. ``false`` means the event was logged but the host was not actually ejected.
	Enforced bool `protobuf:"varint,8,opt,name=enforced,proto3" json:"enforced,omitempty"`
	// Types that are valid to be assigned to Event:
	//	*OutlierDetectionEvent_EjectSuccessRateEvent
	//	*OutlierDetectionEvent_EjectConsecutiveEvent
	Event                isOutlierDetectionEvent_Event `protobuf_oneof:"event"`
	XXX_NoUnkeyedLiteral struct{}                      `json:"-"`
	XXX_unrecognized     []byte                        `json:"-"`
	XXX_sizecache        int32                         `json:"-"`
}

func (m *OutlierDetectionEvent) Reset()         { *m = OutlierDetectionEvent{} }
func (m *OutlierDetectionEvent) String() string { return proto.CompactTextString(m) }
func (*OutlierDetectionEvent) ProtoMessage()    {}
func (*OutlierDetectionEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_5e03c92c55863094, []int{0}
}

func (m *OutlierDetectionEvent) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OutlierDetectionEvent.Unmarshal(m, b)
}
func (m *OutlierDetectionEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OutlierDetectionEvent.Marshal(b, m, deterministic)
}
func (m *OutlierDetectionEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OutlierDetectionEvent.Merge(m, src)
}
func (m *OutlierDetectionEvent) XXX_Size() int {
	return xxx_messageInfo_OutlierDetectionEvent.Size(m)
}
func (m *OutlierDetectionEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_OutlierDetectionEvent.DiscardUnknown(m)
}

var xxx_messageInfo_OutlierDetectionEvent proto.InternalMessageInfo

func (m *OutlierDetectionEvent) GetType() OutlierEjectionType {
	if m != nil {
		return m.Type
	}
	return OutlierEjectionType_CONSECUTIVE_5XX
}

func (m *OutlierDetectionEvent) GetTimestamp() *timestamp.Timestamp {
	if m != nil {
		return m.Timestamp
	}
	return nil
}

func (m *OutlierDetectionEvent) GetSecsSinceLastAction() *wrappers.UInt64Value {
	if m != nil {
		return m.SecsSinceLastAction
	}
	return nil
}

func (m *OutlierDetectionEvent) GetClusterName() string {
	if m != nil {
		return m.ClusterName
	}
	return ""
}

func (m *OutlierDetectionEvent) GetUpstreamUrl() string {
	if m != nil {
		return m.UpstreamUrl
	}
	return ""
}

func (m *OutlierDetectionEvent) GetAction() Action {
	if m != nil {
		return m.Action
	}
	return Action_EJECT
}

func (m *OutlierDetectionEvent) GetNumEjections() uint32 {
	if m != nil {
		return m.NumEjections
	}
	return 0
}

func (m *OutlierDetectionEvent) GetEnforced() bool {
	if m != nil {
		return m.Enforced
	}
	return false
}

type isOutlierDetectionEvent_Event interface {
	isOutlierDetectionEvent_Event()
}

type OutlierDetectionEvent_EjectSuccessRateEvent struct {
	EjectSuccessRateEvent *OutlierEjectSuccessRate `protobuf:"bytes,9,opt,name=eject_success_rate_event,json=ejectSuccessRateEvent,proto3,oneof"`
}

type OutlierDetectionEvent_EjectConsecutiveEvent struct {
	EjectConsecutiveEvent *OutlierEjectConsecutive `protobuf:"bytes,10,opt,name=eject_consecutive_event,json=ejectConsecutiveEvent,proto3,oneof"`
}

func (*OutlierDetectionEvent_EjectSuccessRateEvent) isOutlierDetectionEvent_Event() {}

func (*OutlierDetectionEvent_EjectConsecutiveEvent) isOutlierDetectionEvent_Event() {}

func (m *OutlierDetectionEvent) GetEvent() isOutlierDetectionEvent_Event {
	if m != nil {
		return m.Event
	}
	return nil
}

func (m *OutlierDetectionEvent) GetEjectSuccessRateEvent() *OutlierEjectSuccessRate {
	if x, ok := m.GetEvent().(*OutlierDetectionEvent_EjectSuccessRateEvent); ok {
		return x.EjectSuccessRateEvent
	}
	return nil
}

func (m *OutlierDetectionEvent) GetEjectConsecutiveEvent() *OutlierEjectConsecutive {
	if x, ok := m.GetEvent().(*OutlierDetectionEvent_EjectConsecutiveEvent); ok {
		return x.EjectConsecutiveEvent
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*OutlierDetectionEvent) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*OutlierDetectionEvent_EjectSuccessRateEvent)(nil),
		(*OutlierDetectionEvent_EjectConsecutiveEvent)(nil),
	}
}

type OutlierEjectSuccessRate struct {
	// Host’s success rate at the time of the ejection event on a 0-100 range.
	HostSuccessRate uint32 `protobuf:"varint,1,opt,name=host_success_rate,json=hostSuccessRate,proto3" json:"host_success_rate,omitempty"`
	// Average success rate of the hosts in the cluster at the time of the ejection event on a 0-100
	// range.
	ClusterAverageSuccessRate uint32 `protobuf:"varint,2,opt,name=cluster_average_success_rate,json=clusterAverageSuccessRate,proto3" json:"cluster_average_success_rate,omitempty"`
	// Success rate ejection threshold at the time of the ejection event.
	ClusterSuccessRateEjectionThreshold uint32   `protobuf:"varint,3,opt,name=cluster_success_rate_ejection_threshold,json=clusterSuccessRateEjectionThreshold,proto3" json:"cluster_success_rate_ejection_threshold,omitempty"`
	XXX_NoUnkeyedLiteral                struct{} `json:"-"`
	XXX_unrecognized                    []byte   `json:"-"`
	XXX_sizecache                       int32    `json:"-"`
}

func (m *OutlierEjectSuccessRate) Reset()         { *m = OutlierEjectSuccessRate{} }
func (m *OutlierEjectSuccessRate) String() string { return proto.CompactTextString(m) }
func (*OutlierEjectSuccessRate) ProtoMessage()    {}
func (*OutlierEjectSuccessRate) Descriptor() ([]byte, []int) {
	return fileDescriptor_5e03c92c55863094, []int{1}
}

func (m *OutlierEjectSuccessRate) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OutlierEjectSuccessRate.Unmarshal(m, b)
}
func (m *OutlierEjectSuccessRate) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OutlierEjectSuccessRate.Marshal(b, m, deterministic)
}
func (m *OutlierEjectSuccessRate) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OutlierEjectSuccessRate.Merge(m, src)
}
func (m *OutlierEjectSuccessRate) XXX_Size() int {
	return xxx_messageInfo_OutlierEjectSuccessRate.Size(m)
}
func (m *OutlierEjectSuccessRate) XXX_DiscardUnknown() {
	xxx_messageInfo_OutlierEjectSuccessRate.DiscardUnknown(m)
}

var xxx_messageInfo_OutlierEjectSuccessRate proto.InternalMessageInfo

func (m *OutlierEjectSuccessRate) GetHostSuccessRate() uint32 {
	if m != nil {
		return m.HostSuccessRate
	}
	return 0
}

func (m *OutlierEjectSuccessRate) GetClusterAverageSuccessRate() uint32 {
	if m != nil {
		return m.ClusterAverageSuccessRate
	}
	return 0
}

func (m *OutlierEjectSuccessRate) GetClusterSuccessRateEjectionThreshold() uint32 {
	if m != nil {
		return m.ClusterSuccessRateEjectionThreshold
	}
	return 0
}

type OutlierEjectConsecutive struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *OutlierEjectConsecutive) Reset()         { *m = OutlierEjectConsecutive{} }
func (m *OutlierEjectConsecutive) String() string { return proto.CompactTextString(m) }
func (*OutlierEjectConsecutive) ProtoMessage()    {}
func (*OutlierEjectConsecutive) Descriptor() ([]byte, []int) {
	return fileDescriptor_5e03c92c55863094, []int{2}
}

func (m *OutlierEjectConsecutive) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_OutlierEjectConsecutive.Unmarshal(m, b)
}
func (m *OutlierEjectConsecutive) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_OutlierEjectConsecutive.Marshal(b, m, deterministic)
}
func (m *OutlierEjectConsecutive) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OutlierEjectConsecutive.Merge(m, src)
}
func (m *OutlierEjectConsecutive) XXX_Size() int {
	return xxx_messageInfo_OutlierEjectConsecutive.Size(m)
}
func (m *OutlierEjectConsecutive) XXX_DiscardUnknown() {
	xxx_messageInfo_OutlierEjectConsecutive.DiscardUnknown(m)
}

var xxx_messageInfo_OutlierEjectConsecutive proto.InternalMessageInfo

func init() {
	proto.RegisterEnum("envoy.data.cluster.v2alpha.OutlierEjectionType", OutlierEjectionType_name, OutlierEjectionType_value)
	proto.RegisterEnum("envoy.data.cluster.v2alpha.Action", Action_name, Action_value)
	proto.RegisterType((*OutlierDetectionEvent)(nil), "envoy.data.cluster.v2alpha.OutlierDetectionEvent")
	proto.RegisterType((*OutlierEjectSuccessRate)(nil), "envoy.data.cluster.v2alpha.OutlierEjectSuccessRate")
	proto.RegisterType((*OutlierEjectConsecutive)(nil), "envoy.data.cluster.v2alpha.OutlierEjectConsecutive")
}

func init() {
	proto.RegisterFile("envoy/data/cluster/v2alpha/outlier_detection_event.proto", fileDescriptor_5e03c92c55863094)
}

var fileDescriptor_5e03c92c55863094 = []byte{
	// 707 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x54, 0xcd, 0x4e, 0xdb, 0x4a,
	0x14, 0x66, 0x42, 0x12, 0xc8, 0xf0, 0x97, 0x6b, 0x2e, 0x17, 0x93, 0x8b, 0x20, 0x0a, 0x8b, 0x46,
	0xa8, 0xb2, 0x25, 0x28, 0x55, 0x57, 0x95, 0x92, 0xd4, 0xb4, 0x20, 0x04, 0xd4, 0x49, 0x28, 0x5d,
	0x54, 0xa3, 0xc1, 0x39, 0x24, 0xa9, 0x6c, 0x8f, 0xe5, 0x19, 0xa7, 0xcd, 0xb6, 0x4f, 0xd0, 0xc7,
	0xe8, 0x23, 0x54, 0x5d, 0xf1, 0x06, 0x7d, 0x84, 0x4a, 0xdd, 0xf1, 0x10, 0x95, 0x2a, 0x8f, 0xc7,
	0x90, 0xf0, 0xa7, 0x76, 0x37, 0x9e, 0x39, 0xdf, 0x77, 0xbe, 0xf3, 0x9d, 0x73, 0x8c, 0x9f, 0x81,
	0x3f, 0x60, 0x43, 0xb3, 0x43, 0x05, 0x35, 0x1d, 0x37, 0xe2, 0x02, 0x42, 0x73, 0xb0, 0x45, 0xdd,
	0xa0, 0x47, 0x4d, 0x16, 0x09, 0xb7, 0x0f, 0x21, 0xe9, 0x80, 0x00, 0x47, 0xf4, 0x99, 0x4f, 0x60,
	0x00, 0xbe, 0x30, 0x82, 0x90, 0x09, 0xa6, 0x95, 0x24, 0xd2, 0x88, 0x91, 0x86, 0x42, 0x1a, 0x0a,
	0x59, 0x5a, 0xef, 0x32, 0xd6, 0x75, 0xc1, 0x94, 0x91, 0x67, 0xd1, 0xb9, 0x29, 0xfa, 0x1e, 0x70,
	0x41, 0xbd, 0x20, 0x01, 0x97, 0xd6, 0x6e, 0x06, 0x7c, 0x08, 0x69, 0x10, 0x40, 0xc8, 0xd5, 0xfb,
	0xf2, 0x80, 0xba, 0xfd, 0x0e, 0x15, 0x60, 0xa6, 0x07, 0xf5, 0xf0, 0x6f, 0x97, 0x75, 0x99, 0x3c,
	0x9a, 0xf1, 0x29, 0xb9, 0xad, 0x7c, 0xcf, 0xe1, 0xa5, 0xa3, 0x44, 0xed, 0x8b, 0x54, 0xac, 0x15,
	0x6b, 0xd5, 0x8e, 0x70, 0x56, 0x0c, 0x03, 0xd0, 0x51, 0x19, 0x55, 0xe7, 0xb7, 0x4c, 0xe3, 0x7e,
	0xd1, 0x86, 0x22, 0xb0, 0xde, 0x27, 0xf8, 0xd6, 0x30, 0x80, 0x3a, 0xfe, 0x76, 0x79, 0x31, 0x99,
	0xfb, 0x84, 0x32, 0x45, 0x64, 0x4b, 0x22, 0xed, 0x39, 0x2e, 0x5c, 0x15, 0xa3, 0x67, 0xca, 0xa8,
	0x3a, 0xb3, 0x55, 0x32, 0x92, 0x6a, 0x8c, 0xb4, 0x1a, 0xa3, 0x95, 0x46, 0xd4, 0xb3, 0x9f, 0x7f,
	0xac, 0x23, 0xfb, 0x1a, 0xa2, 0xbd, 0xc6, 0xff, 0x71, 0x70, 0x38, 0xe1, 0x7d, 0xdf, 0x01, 0xe2,
	0x52, 0x2e, 0x08, 0x95, 0xf9, 0xf4, 0x49, 0x49, 0xb6, 0x7a, 0x8b, 0xac, 0xbd, 0xe7, 0x8b, 0xa7,
	0x4f, 0x4e, 0xa8, 0x1b, 0x81, 0xbd, 0x18, 0x63, 0x9b, 0x31, 0xf4, 0x80, 0x72, 0x51, 0x93, 0x40,
	0xed, 0x31, 0x9e, 0x55, 0xb5, 0x10, 0x9f, 0x7a, 0xa0, 0x67, 0xcb, 0xa8, 0x5a, 0xa8, 0x17, 0x62,
	0xe9, 0xd9, 0x30, 0x53, 0x46, 0xf6, 0x8c, 0x7a, 0x3e, 0xa4, 0x1e, 0xc4, 0xd1, 0x51, 0xc0, 0x45,
	0x08, 0xd4, 0x23, 0x51, 0xe8, 0xea, 0xb9, 0x5b, 0xd1, 0xe9, 0x73, 0x3b, 0x74, 0xb5, 0x5d, 0x9c,
	0x57, 0xf2, 0xf2, 0xd2, 0xc1, 0xca, 0x43, 0x0e, 0x26, 0x7a, 0xc6, 0x4c, 0x53, 0x68, 0x6d, 0x03,
	0xcf, 0xf9, 0x91, 0x47, 0x40, 0x99, 0xcb, 0xf5, 0xa9, 0x32, 0xaa, 0xce, 0xd9, 0xb3, 0x7e, 0xe4,
	0xa5, 0x86, 0x73, 0xad, 0x84, 0xa7, 0xc1, 0x3f, 0x67, 0xa1, 0x03, 0x1d, 0x7d, 0xba, 0x8c, 0xaa,
	0xd3, 0xf6, 0xd5, 0xb7, 0xe6, 0x63, 0x5d, 0x82, 0x09, 0x8f, 0x1c, 0x07, 0x38, 0x27, 0x21, 0x15,
	0x90, 0x0c, 0xa4, 0x5e, 0x90, 0xce, 0x6d, 0xff, 0x69, 0x73, 0x9b, 0x09, 0x83, 0x4d, 0x05, 0xbc,
	0x9a, 0xb0, 0x97, 0xe0, 0xc6, 0x5d, 0x32, 0x38, 0x1e, 0x5e, 0x4e, 0xf2, 0x39, 0xcc, 0xe7, 0xe0,
	0x44, 0xa2, 0x3f, 0x48, 0xd3, 0xe1, 0xbf, 0x4b, 0xd7, 0xb8, 0x26, 0xb8, 0x4a, 0x37, 0x72, 0x27,
	0xd3, 0xd5, 0xe7, 0x71, 0x4e, 0x92, 0x6b, 0xb9, 0xaf, 0x97, 0x17, 0x93, 0xa8, 0xf2, 0x0b, 0xe1,
	0xe5, 0x7b, 0x34, 0x6b, 0x3b, 0xf8, 0x9f, 0x1e, 0xe3, 0xe3, 0x4e, 0xc8, 0x01, 0x9f, 0x53, 0x6d,
	0xdc, 0xcc, 0xe8, 0x1d, 0x7b, 0x21, 0x8e, 0x19, 0x85, 0xed, 0xe3, 0xd5, 0x74, 0x4c, 0xe8, 0x00,
	0x42, 0xda, 0x85, 0x71, 0x86, 0xcc, 0x4d, 0x86, 0x15, 0x15, 0x5e, 0x4b, 0xa2, 0x47, 0xb9, 0x08,
	0x7e, 0x94, 0x72, 0x8d, 0xf7, 0x43, 0xf5, 0x92, 0x88, 0x5e, 0x08, 0xbc, 0xc7, 0xdc, 0x8e, 0x1c,
	0xeb, 0x31, 0xda, 0x0d, 0x85, 0x1c, 0xb5, 0x3c, 0xdd, 0xb9, 0x14, 0x55, 0x59, 0x19, 0x2f, 0x7f,
	0xc4, 0xaf, 0xcd, 0x77, 0x78, 0xf1, 0x8e, 0x55, 0xd5, 0x16, 0xf1, 0x42, 0xe3, 0xe8, 0xb0, 0x69,
	0x35, 0xda, 0xad, 0xbd, 0x13, 0x8b, 0xec, 0x9c, 0x9e, 0x16, 0x27, 0xb4, 0x75, 0xfc, 0xff, 0xe8,
	0xe5, 0xcb, 0x5a, 0xcb, 0x7a, 0x53, 0x7b, 0x4b, 0x76, 0x6b, 0x7b, 0x07, 0x6d, 0xdb, 0x2a, 0x22,
	0xad, 0x88, 0x67, 0x9b, 0xed, 0x46, 0xc3, 0x6a, 0x36, 0x89, 0x5d, 0x6b, 0x59, 0xc5, 0xcc, 0x66,
	0x19, 0xe7, 0xd5, 0x5e, 0x15, 0x70, 0xce, 0xda, 0xb7, 0x1a, 0xad, 0xe2, 0x84, 0x36, 0x83, 0xa7,
	0xda, 0x87, 0xc9, 0x07, 0xaa, 0x1f, 0x7c, 0xf9, 0xb9, 0x86, 0x70, 0xb5, 0xcf, 0x92, 0x09, 0x08,
	0x42, 0xf6, 0x71, 0xf8, 0xc0, 0x30, 0xd4, 0x4b, 0x77, 0xfe, 0x9a, 0x8e, 0xe3, 0xfd, 0x3e, 0x46,
	0x67, 0x79, 0xb9, 0xe8, 0xdb, 0xbf, 0x03, 0x00, 0x00, 0xff, 0xff, 0xbf, 0xdc, 0x03, 0xe6, 0x8a,
	0x05, 0x00, 0x00,
}