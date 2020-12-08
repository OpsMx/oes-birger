// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.14.0
// source: tunnel/tunnel.proto

package tunnel

import (
	context "context"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type PingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ts uint64 `protobuf:"varint,2,opt,name=ts,proto3" json:"ts,omitempty"`
}

func (x *PingRequest) Reset() {
	*x = PingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_tunnel_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingRequest) ProtoMessage() {}

func (x *PingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_tunnel_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingRequest.ProtoReflect.Descriptor instead.
func (*PingRequest) Descriptor() ([]byte, []int) {
	return file_tunnel_tunnel_proto_rawDescGZIP(), []int{0}
}

func (x *PingRequest) GetTs() uint64 {
	if x != nil {
		return x.Ts
	}
	return 0
}

type PingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ts       uint64 `protobuf:"varint,2,opt,name=ts,proto3" json:"ts,omitempty"`
	EchoedTs uint64 `protobuf:"varint,3,opt,name=echoedTs,proto3" json:"echoedTs,omitempty"`
}

func (x *PingResponse) Reset() {
	*x = PingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_tunnel_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingResponse) ProtoMessage() {}

func (x *PingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_tunnel_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingResponse.ProtoReflect.Descriptor instead.
func (*PingResponse) Descriptor() ([]byte, []int) {
	return file_tunnel_tunnel_proto_rawDescGZIP(), []int{1}
}

func (x *PingResponse) GetTs() uint64 {
	if x != nil {
		return x.Ts
	}
	return 0
}

func (x *PingResponse) GetEchoedTs() uint64 {
	if x != nil {
		return x.EchoedTs
	}
	return 0
}

type HttpHeader struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name   string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Values []string `protobuf:"bytes,2,rep,name=values,proto3" json:"values,omitempty"`
}

func (x *HttpHeader) Reset() {
	*x = HttpHeader{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_tunnel_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HttpHeader) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HttpHeader) ProtoMessage() {}

func (x *HttpHeader) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_tunnel_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HttpHeader.ProtoReflect.Descriptor instead.
func (*HttpHeader) Descriptor() ([]byte, []int) {
	return file_tunnel_tunnel_proto_rawDescGZIP(), []int{2}
}

func (x *HttpHeader) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *HttpHeader) GetValues() []string {
	if x != nil {
		return x.Values
	}
	return nil
}

type HttpRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id      string        `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Target  string        `protobuf:"bytes,2,opt,name=target,proto3" json:"target,omitempty"`
	Method  string        `protobuf:"bytes,4,opt,name=method,proto3" json:"method,omitempty"`
	URI     string        `protobuf:"bytes,5,opt,name=URI,proto3" json:"URI,omitempty"`
	Headers []*HttpHeader `protobuf:"bytes,6,rep,name=headers,proto3" json:"headers,omitempty"`
	Body    []byte        `protobuf:"bytes,7,opt,name=body,proto3" json:"body,omitempty"`
}

func (x *HttpRequest) Reset() {
	*x = HttpRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_tunnel_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HttpRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HttpRequest) ProtoMessage() {}

func (x *HttpRequest) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_tunnel_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HttpRequest.ProtoReflect.Descriptor instead.
func (*HttpRequest) Descriptor() ([]byte, []int) {
	return file_tunnel_tunnel_proto_rawDescGZIP(), []int{3}
}

func (x *HttpRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *HttpRequest) GetTarget() string {
	if x != nil {
		return x.Target
	}
	return ""
}

func (x *HttpRequest) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *HttpRequest) GetURI() string {
	if x != nil {
		return x.URI
	}
	return ""
}

func (x *HttpRequest) GetHeaders() []*HttpHeader {
	if x != nil {
		return x.Headers
	}
	return nil
}

func (x *HttpRequest) GetBody() []byte {
	if x != nil {
		return x.Body
	}
	return nil
}

// This is the initial response sent to the controller from the agent.  If contentLength == len(body),
// the transmission is complete.  Otherwise, the controller should expect to see following
// HttpChunkedResponse messages, where EOF is indicated with a body length of zero.
type HttpResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id            string        `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Target        string        `protobuf:"bytes,2,opt,name=target,proto3" json:"target,omitempty"`
	Status        int32         `protobuf:"varint,3,opt,name=status,proto3" json:"status,omitempty"`
	Headers       []*HttpHeader `protobuf:"bytes,4,rep,name=headers,proto3" json:"headers,omitempty"`
	Body          []byte        `protobuf:"bytes,5,opt,name=body,proto3" json:"body,omitempty"`
	ContentLength int64         `protobuf:"varint,6,opt,name=contentLength,proto3" json:"contentLength,omitempty"`
}

func (x *HttpResponse) Reset() {
	*x = HttpResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_tunnel_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HttpResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HttpResponse) ProtoMessage() {}

func (x *HttpResponse) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_tunnel_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HttpResponse.ProtoReflect.Descriptor instead.
func (*HttpResponse) Descriptor() ([]byte, []int) {
	return file_tunnel_tunnel_proto_rawDescGZIP(), []int{4}
}

func (x *HttpResponse) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *HttpResponse) GetTarget() string {
	if x != nil {
		return x.Target
	}
	return ""
}

func (x *HttpResponse) GetStatus() int32 {
	if x != nil {
		return x.Status
	}
	return 0
}

func (x *HttpResponse) GetHeaders() []*HttpHeader {
	if x != nil {
		return x.Headers
	}
	return nil
}

func (x *HttpResponse) GetBody() []byte {
	if x != nil {
		return x.Body
	}
	return nil
}

func (x *HttpResponse) GetContentLength() int64 {
	if x != nil {
		return x.ContentLength
	}
	return 0
}

type HttpChunkedResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id     string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Target string `protobuf:"bytes,2,opt,name=target,proto3" json:"target,omitempty"`
	Body   []byte `protobuf:"bytes,3,opt,name=body,proto3" json:"body,omitempty"`
}

func (x *HttpChunkedResponse) Reset() {
	*x = HttpChunkedResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_tunnel_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HttpChunkedResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HttpChunkedResponse) ProtoMessage() {}

func (x *HttpChunkedResponse) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_tunnel_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HttpChunkedResponse.ProtoReflect.Descriptor instead.
func (*HttpChunkedResponse) Descriptor() ([]byte, []int) {
	return file_tunnel_tunnel_proto_rawDescGZIP(), []int{5}
}

func (x *HttpChunkedResponse) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *HttpChunkedResponse) GetTarget() string {
	if x != nil {
		return x.Target
	}
	return ""
}

func (x *HttpChunkedResponse) GetBody() []byte {
	if x != nil {
		return x.Body
	}
	return nil
}

// Messages sent from server to agent
type SAEventWrapper struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Event:
	//	*SAEventWrapper_PingResponse
	//	*SAEventWrapper_HttpRequest
	Event isSAEventWrapper_Event `protobuf_oneof:"event"`
}

func (x *SAEventWrapper) Reset() {
	*x = SAEventWrapper{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_tunnel_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SAEventWrapper) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SAEventWrapper) ProtoMessage() {}

func (x *SAEventWrapper) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_tunnel_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SAEventWrapper.ProtoReflect.Descriptor instead.
func (*SAEventWrapper) Descriptor() ([]byte, []int) {
	return file_tunnel_tunnel_proto_rawDescGZIP(), []int{6}
}

func (m *SAEventWrapper) GetEvent() isSAEventWrapper_Event {
	if m != nil {
		return m.Event
	}
	return nil
}

func (x *SAEventWrapper) GetPingResponse() *PingResponse {
	if x, ok := x.GetEvent().(*SAEventWrapper_PingResponse); ok {
		return x.PingResponse
	}
	return nil
}

func (x *SAEventWrapper) GetHttpRequest() *HttpRequest {
	if x, ok := x.GetEvent().(*SAEventWrapper_HttpRequest); ok {
		return x.HttpRequest
	}
	return nil
}

type isSAEventWrapper_Event interface {
	isSAEventWrapper_Event()
}

type SAEventWrapper_PingResponse struct {
	PingResponse *PingResponse `protobuf:"bytes,1,opt,name=pingResponse,proto3,oneof"`
}

type SAEventWrapper_HttpRequest struct {
	HttpRequest *HttpRequest `protobuf:"bytes,2,opt,name=httpRequest,proto3,oneof"`
}

func (*SAEventWrapper_PingResponse) isSAEventWrapper_Event() {}

func (*SAEventWrapper_HttpRequest) isSAEventWrapper_Event() {}

// Messages sent from agent to server
type ASEventWrapper struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Event:
	//	*ASEventWrapper_PingRequest
	//	*ASEventWrapper_HttpResponse
	//	*ASEventWrapper_HttpChunkedResponse
	Event isASEventWrapper_Event `protobuf_oneof:"event"`
}

func (x *ASEventWrapper) Reset() {
	*x = ASEventWrapper{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tunnel_tunnel_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ASEventWrapper) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ASEventWrapper) ProtoMessage() {}

func (x *ASEventWrapper) ProtoReflect() protoreflect.Message {
	mi := &file_tunnel_tunnel_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ASEventWrapper.ProtoReflect.Descriptor instead.
func (*ASEventWrapper) Descriptor() ([]byte, []int) {
	return file_tunnel_tunnel_proto_rawDescGZIP(), []int{7}
}

func (m *ASEventWrapper) GetEvent() isASEventWrapper_Event {
	if m != nil {
		return m.Event
	}
	return nil
}

func (x *ASEventWrapper) GetPingRequest() *PingRequest {
	if x, ok := x.GetEvent().(*ASEventWrapper_PingRequest); ok {
		return x.PingRequest
	}
	return nil
}

func (x *ASEventWrapper) GetHttpResponse() *HttpResponse {
	if x, ok := x.GetEvent().(*ASEventWrapper_HttpResponse); ok {
		return x.HttpResponse
	}
	return nil
}

func (x *ASEventWrapper) GetHttpChunkedResponse() *HttpChunkedResponse {
	if x, ok := x.GetEvent().(*ASEventWrapper_HttpChunkedResponse); ok {
		return x.HttpChunkedResponse
	}
	return nil
}

type isASEventWrapper_Event interface {
	isASEventWrapper_Event()
}

type ASEventWrapper_PingRequest struct {
	PingRequest *PingRequest `protobuf:"bytes,1,opt,name=pingRequest,proto3,oneof"`
}

type ASEventWrapper_HttpResponse struct {
	HttpResponse *HttpResponse `protobuf:"bytes,2,opt,name=httpResponse,proto3,oneof"`
}

type ASEventWrapper_HttpChunkedResponse struct {
	HttpChunkedResponse *HttpChunkedResponse `protobuf:"bytes,3,opt,name=httpChunkedResponse,proto3,oneof"`
}

func (*ASEventWrapper_PingRequest) isASEventWrapper_Event() {}

func (*ASEventWrapper_HttpResponse) isASEventWrapper_Event() {}

func (*ASEventWrapper_HttpChunkedResponse) isASEventWrapper_Event() {}

var File_tunnel_tunnel_proto protoreflect.FileDescriptor

var file_tunnel_tunnel_proto_rawDesc = []byte{
	0x0a, 0x13, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x2f, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x22, 0x1d, 0x0a,
	0x0b, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02,
	0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x02, 0x74, 0x73, 0x22, 0x3a, 0x0a, 0x0c,
	0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x0e, 0x0a, 0x02,
	0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x02, 0x74, 0x73, 0x12, 0x1a, 0x0a, 0x08,
	0x65, 0x63, 0x68, 0x6f, 0x65, 0x64, 0x54, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08,
	0x65, 0x63, 0x68, 0x6f, 0x65, 0x64, 0x54, 0x73, 0x22, 0x38, 0x0a, 0x0a, 0x48, 0x74, 0x74, 0x70,
	0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x73, 0x22, 0xa1, 0x01, 0x0a, 0x0b, 0x48, 0x74, 0x74, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02,
	0x69, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x6d, 0x65,
	0x74, 0x68, 0x6f, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6d, 0x65, 0x74, 0x68,
	0x6f, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x55, 0x52, 0x49, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x55, 0x52, 0x49, 0x12, 0x2c, 0x0a, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x18,
	0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x48,
	0x74, 0x74, 0x70, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x22, 0xb6, 0x01, 0x0a, 0x0c, 0x48, 0x74, 0x74, 0x70, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12,
	0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x2c, 0x0a, 0x07, 0x68, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x74, 0x75, 0x6e, 0x6e, 0x65,
	0x6c, 0x2e, 0x48, 0x74, 0x74, 0x70, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x07, 0x68, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x12, 0x24, 0x0a, 0x0d, 0x63, 0x6f, 0x6e,
	0x74, 0x65, 0x6e, 0x74, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x22,
	0x51, 0x0a, 0x13, 0x48, 0x74, 0x74, 0x70, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x65, 0x64, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x12,
	0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x62, 0x6f,
	0x64, 0x79, 0x22, 0x8e, 0x01, 0x0a, 0x0e, 0x53, 0x41, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x57, 0x72,
	0x61, 0x70, 0x70, 0x65, 0x72, 0x12, 0x3a, 0x0a, 0x0c, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x74, 0x75,
	0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x48, 0x00, 0x52, 0x0c, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x37, 0x0a, 0x0b, 0x68, 0x74, 0x74, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x2e,
	0x48, 0x74, 0x74, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x0b, 0x68,
	0x74, 0x74, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x42, 0x07, 0x0a, 0x05, 0x65, 0x76,
	0x65, 0x6e, 0x74, 0x22, 0xdf, 0x01, 0x0a, 0x0e, 0x41, 0x53, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x57,
	0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x12, 0x37, 0x0a, 0x0b, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x74, 0x75,
	0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x48, 0x00, 0x52, 0x0b, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x3a, 0x0a, 0x0c, 0x68, 0x74, 0x74, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x48,
	0x74, 0x74, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x48, 0x00, 0x52, 0x0c, 0x68,
	0x74, 0x74, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4f, 0x0a, 0x13, 0x68,
	0x74, 0x74, 0x70, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x65, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x74, 0x75, 0x6e, 0x6e, 0x65,
	0x6c, 0x2e, 0x48, 0x74, 0x74, 0x70, 0x43, 0x68, 0x75, 0x6e, 0x6b, 0x65, 0x64, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x48, 0x00, 0x52, 0x13, 0x68, 0x74, 0x74, 0x70, 0x43, 0x68, 0x75,
	0x6e, 0x6b, 0x65, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x07, 0x0a, 0x05,
	0x65, 0x76, 0x65, 0x6e, 0x74, 0x32, 0x54, 0x0a, 0x0d, 0x54, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x43, 0x0a, 0x0b, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x54,
	0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x12, 0x16, 0x2e, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x41,
	0x53, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x57, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x1a, 0x16, 0x2e,
	0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x2e, 0x53, 0x41, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x57, 0x72,
	0x61, 0x70, 0x70, 0x65, 0x72, 0x22, 0x00, 0x28, 0x01, 0x30, 0x01, 0x42, 0x0a, 0x5a, 0x08, 0x2e,
	0x3b, 0x74, 0x75, 0x6e, 0x6e, 0x65, 0x6c, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_tunnel_tunnel_proto_rawDescOnce sync.Once
	file_tunnel_tunnel_proto_rawDescData = file_tunnel_tunnel_proto_rawDesc
)

func file_tunnel_tunnel_proto_rawDescGZIP() []byte {
	file_tunnel_tunnel_proto_rawDescOnce.Do(func() {
		file_tunnel_tunnel_proto_rawDescData = protoimpl.X.CompressGZIP(file_tunnel_tunnel_proto_rawDescData)
	})
	return file_tunnel_tunnel_proto_rawDescData
}

var file_tunnel_tunnel_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_tunnel_tunnel_proto_goTypes = []interface{}{
	(*PingRequest)(nil),         // 0: tunnel.PingRequest
	(*PingResponse)(nil),        // 1: tunnel.PingResponse
	(*HttpHeader)(nil),          // 2: tunnel.HttpHeader
	(*HttpRequest)(nil),         // 3: tunnel.HttpRequest
	(*HttpResponse)(nil),        // 4: tunnel.HttpResponse
	(*HttpChunkedResponse)(nil), // 5: tunnel.HttpChunkedResponse
	(*SAEventWrapper)(nil),      // 6: tunnel.SAEventWrapper
	(*ASEventWrapper)(nil),      // 7: tunnel.ASEventWrapper
}
var file_tunnel_tunnel_proto_depIdxs = []int32{
	2, // 0: tunnel.HttpRequest.headers:type_name -> tunnel.HttpHeader
	2, // 1: tunnel.HttpResponse.headers:type_name -> tunnel.HttpHeader
	1, // 2: tunnel.SAEventWrapper.pingResponse:type_name -> tunnel.PingResponse
	3, // 3: tunnel.SAEventWrapper.httpRequest:type_name -> tunnel.HttpRequest
	0, // 4: tunnel.ASEventWrapper.pingRequest:type_name -> tunnel.PingRequest
	4, // 5: tunnel.ASEventWrapper.httpResponse:type_name -> tunnel.HttpResponse
	5, // 6: tunnel.ASEventWrapper.httpChunkedResponse:type_name -> tunnel.HttpChunkedResponse
	7, // 7: tunnel.TunnelService.EventTunnel:input_type -> tunnel.ASEventWrapper
	6, // 8: tunnel.TunnelService.EventTunnel:output_type -> tunnel.SAEventWrapper
	8, // [8:9] is the sub-list for method output_type
	7, // [7:8] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_tunnel_tunnel_proto_init() }
func file_tunnel_tunnel_proto_init() {
	if File_tunnel_tunnel_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_tunnel_tunnel_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PingRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_tunnel_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PingResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_tunnel_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HttpHeader); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_tunnel_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HttpRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_tunnel_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HttpResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_tunnel_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HttpChunkedResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_tunnel_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SAEventWrapper); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_tunnel_tunnel_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ASEventWrapper); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_tunnel_tunnel_proto_msgTypes[6].OneofWrappers = []interface{}{
		(*SAEventWrapper_PingResponse)(nil),
		(*SAEventWrapper_HttpRequest)(nil),
	}
	file_tunnel_tunnel_proto_msgTypes[7].OneofWrappers = []interface{}{
		(*ASEventWrapper_PingRequest)(nil),
		(*ASEventWrapper_HttpResponse)(nil),
		(*ASEventWrapper_HttpChunkedResponse)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_tunnel_tunnel_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_tunnel_tunnel_proto_goTypes,
		DependencyIndexes: file_tunnel_tunnel_proto_depIdxs,
		MessageInfos:      file_tunnel_tunnel_proto_msgTypes,
	}.Build()
	File_tunnel_tunnel_proto = out.File
	file_tunnel_tunnel_proto_rawDesc = nil
	file_tunnel_tunnel_proto_goTypes = nil
	file_tunnel_tunnel_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// TunnelServiceClient is the client API for TunnelService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type TunnelServiceClient interface {
	EventTunnel(ctx context.Context, opts ...grpc.CallOption) (TunnelService_EventTunnelClient, error)
}

type tunnelServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTunnelServiceClient(cc grpc.ClientConnInterface) TunnelServiceClient {
	return &tunnelServiceClient{cc}
}

func (c *tunnelServiceClient) EventTunnel(ctx context.Context, opts ...grpc.CallOption) (TunnelService_EventTunnelClient, error) {
	stream, err := c.cc.NewStream(ctx, &_TunnelService_serviceDesc.Streams[0], "/tunnel.TunnelService/EventTunnel", opts...)
	if err != nil {
		return nil, err
	}
	x := &tunnelServiceEventTunnelClient{stream}
	return x, nil
}

type TunnelService_EventTunnelClient interface {
	Send(*ASEventWrapper) error
	Recv() (*SAEventWrapper, error)
	grpc.ClientStream
}

type tunnelServiceEventTunnelClient struct {
	grpc.ClientStream
}

func (x *tunnelServiceEventTunnelClient) Send(m *ASEventWrapper) error {
	return x.ClientStream.SendMsg(m)
}

func (x *tunnelServiceEventTunnelClient) Recv() (*SAEventWrapper, error) {
	m := new(SAEventWrapper)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// TunnelServiceServer is the server API for TunnelService service.
type TunnelServiceServer interface {
	EventTunnel(TunnelService_EventTunnelServer) error
}

// UnimplementedTunnelServiceServer can be embedded to have forward compatible implementations.
type UnimplementedTunnelServiceServer struct {
}

func (*UnimplementedTunnelServiceServer) EventTunnel(TunnelService_EventTunnelServer) error {
	return status.Errorf(codes.Unimplemented, "method EventTunnel not implemented")
}

func RegisterTunnelServiceServer(s *grpc.Server, srv TunnelServiceServer) {
	s.RegisterService(&_TunnelService_serviceDesc, srv)
}

func _TunnelService_EventTunnel_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(TunnelServiceServer).EventTunnel(&tunnelServiceEventTunnelServer{stream})
}

type TunnelService_EventTunnelServer interface {
	Send(*SAEventWrapper) error
	Recv() (*ASEventWrapper, error)
	grpc.ServerStream
}

type tunnelServiceEventTunnelServer struct {
	grpc.ServerStream
}

func (x *tunnelServiceEventTunnelServer) Send(m *SAEventWrapper) error {
	return x.ServerStream.SendMsg(m)
}

func (x *tunnelServiceEventTunnelServer) Recv() (*ASEventWrapper, error) {
	m := new(ASEventWrapper)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _TunnelService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "tunnel.TunnelService",
	HandlerType: (*TunnelServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "EventTunnel",
			Handler:       _TunnelService_EventTunnel_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "tunnel/tunnel.proto",
}
