// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.17.1
// source: pbschema/jwtsigner.proto

package jwtsigner_pb

import (
	"github.com/Golang-Tools/jwthelper/jwt_pb"
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

type MetaRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *MetaRequest) Reset() {
	*x = MetaRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbschema_jwtsigner_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MetaRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MetaRequest) ProtoMessage() {}

func (x *MetaRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pbschema_jwtsigner_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MetaRequest.ProtoReflect.Descriptor instead.
func (*MetaRequest) Descriptor() ([]byte, []int) {
	return file_pbschema_jwtsigner_proto_rawDescGZIP(), []int{0}
}

type MetaResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status *jwt_pb.ResponseStatus `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
	Data   *jwt_pb.SignerMeta     `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *MetaResponse) Reset() {
	*x = MetaResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbschema_jwtsigner_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MetaResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MetaResponse) ProtoMessage() {}

func (x *MetaResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pbschema_jwtsigner_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MetaResponse.ProtoReflect.Descriptor instead.
func (*MetaResponse) Descriptor() ([]byte, []int) {
	return file_pbschema_jwtsigner_proto_rawDescGZIP(), []int{1}
}

func (x *MetaResponse) GetStatus() *jwt_pb.ResponseStatus {
	if x != nil {
		return x.Status
	}
	return nil
}

func (x *MetaResponse) GetData() *jwt_pb.SignerMeta {
	if x != nil {
		return x.Data
	}
	return nil
}

type SignRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Sub     string   `protobuf:"bytes,1,opt,name=sub,proto3" json:"sub,omitempty"`          //设置主题,一般用于放用户id
	Exp     int64    `protobuf:"varint,2,opt,name=exp,proto3" json:"exp,omitempty"`         //超时时间,秒级时间戳
	Nbf     int64    `protobuf:"varint,3,opt,name=nbf,proto3" json:"nbf,omitempty"`         //生效时间,秒级时间戳
	Refresh int32    `protobuf:"varint,4,opt,name=refresh,proto3" json:"refresh,omitempty"` //>=0设置RefreshToken,单位是hour
	Payload []byte   `protobuf:"bytes,5,opt,name=payload,proto3" json:"payload,omitempty"`  //其他负载,请以json格式传输
	Aud     []string `protobuf:"bytes,6,rep,name=aud,proto3" json:"aud,omitempty"`          //设置签名接收方,一般是app名或者url
}

func (x *SignRequest) Reset() {
	*x = SignRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbschema_jwtsigner_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignRequest) ProtoMessage() {}

func (x *SignRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pbschema_jwtsigner_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignRequest.ProtoReflect.Descriptor instead.
func (*SignRequest) Descriptor() ([]byte, []int) {
	return file_pbschema_jwtsigner_proto_rawDescGZIP(), []int{2}
}

func (x *SignRequest) GetSub() string {
	if x != nil {
		return x.Sub
	}
	return ""
}

func (x *SignRequest) GetExp() int64 {
	if x != nil {
		return x.Exp
	}
	return 0
}

func (x *SignRequest) GetNbf() int64 {
	if x != nil {
		return x.Nbf
	}
	return 0
}

func (x *SignRequest) GetRefresh() int32 {
	if x != nil {
		return x.Refresh
	}
	return 0
}

func (x *SignRequest) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *SignRequest) GetAud() []string {
	if x != nil {
		return x.Aud
	}
	return nil
}

type SignResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status *jwt_pb.ResponseStatus `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
	Token  *jwt_pb.Token          `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
}

func (x *SignResponse) Reset() {
	*x = SignResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pbschema_jwtsigner_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignResponse) ProtoMessage() {}

func (x *SignResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pbschema_jwtsigner_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignResponse.ProtoReflect.Descriptor instead.
func (*SignResponse) Descriptor() ([]byte, []int) {
	return file_pbschema_jwtsigner_proto_rawDescGZIP(), []int{3}
}

func (x *SignResponse) GetStatus() *jwt_pb.ResponseStatus {
	if x != nil {
		return x.Status
	}
	return nil
}

func (x *SignResponse) GetToken() *jwt_pb.Token {
	if x != nil {
		return x.Token
	}
	return nil
}

var File_pbschema_jwtsigner_proto protoreflect.FileDescriptor

var file_pbschema_jwtsigner_proto_rawDesc = []byte{
	0x0a, 0x18, 0x70, 0x62, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2f, 0x6a, 0x77, 0x74, 0x73, 0x69,
	0x67, 0x6e, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x6a, 0x77, 0x74, 0x2e,
	0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x1a, 0x12, 0x70, 0x62, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61,
	0x2f, 0x6a, 0x77, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x0d, 0x0a, 0x0b, 0x4d, 0x65,
	0x74, 0x61, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x60, 0x0a, 0x0c, 0x4d, 0x65, 0x74,
	0x61, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2b, 0x0a, 0x06, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x6a, 0x77, 0x74, 0x2e,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06,
	0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x23, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6a, 0x77, 0x74, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x65,
	0x72, 0x4d, 0x65, 0x74, 0x61, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0x89, 0x01, 0x0a, 0x0b,
	0x53, 0x69, 0x67, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x73,
	0x75, 0x62, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x73, 0x75, 0x62, 0x12, 0x10, 0x0a,
	0x03, 0x65, 0x78, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x03, 0x65, 0x78, 0x70, 0x12,
	0x10, 0x0a, 0x03, 0x6e, 0x62, 0x66, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x03, 0x6e, 0x62,
	0x66, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x12, 0x18, 0x0a, 0x07, 0x70,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x61,
	0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x61, 0x75, 0x64, 0x18, 0x06, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x03, 0x61, 0x75, 0x64, 0x22, 0x5d, 0x0a, 0x0c, 0x53, 0x69, 0x67, 0x6e, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2b, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x6a, 0x77, 0x74, 0x2e, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x12, 0x20, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x6a, 0x77, 0x74, 0x2e, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52,
	0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x32, 0x86, 0x01, 0x0a, 0x0a, 0x4a, 0x77, 0x74, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x3b, 0x0a, 0x04, 0x4d, 0x65, 0x74, 0x61, 0x12, 0x17, 0x2e,
	0x6a, 0x77, 0x74, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x6a, 0x77, 0x74, 0x2e, 0x73, 0x69, 0x67,
	0x6e, 0x65, 0x72, 0x2e, 0x4d, 0x65, 0x74, 0x61, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x00, 0x12, 0x3b, 0x0a, 0x04, 0x53, 0x69, 0x67, 0x6e, 0x12, 0x17, 0x2e, 0x6a, 0x77, 0x74,
	0x2e, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x6a, 0x77, 0x74, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72,
	0x2e, 0x53, 0x69, 0x67, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42,
	0x10, 0x5a, 0x0e, 0x2e, 0x2f, 0x6a, 0x77, 0x74, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72, 0x5f, 0x70,
	0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pbschema_jwtsigner_proto_rawDescOnce sync.Once
	file_pbschema_jwtsigner_proto_rawDescData = file_pbschema_jwtsigner_proto_rawDesc
)

func file_pbschema_jwtsigner_proto_rawDescGZIP() []byte {
	file_pbschema_jwtsigner_proto_rawDescOnce.Do(func() {
		file_pbschema_jwtsigner_proto_rawDescData = protoimpl.X.CompressGZIP(file_pbschema_jwtsigner_proto_rawDescData)
	})
	return file_pbschema_jwtsigner_proto_rawDescData
}

var file_pbschema_jwtsigner_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_pbschema_jwtsigner_proto_goTypes = []interface{}{
	(*MetaRequest)(nil),           // 0: jwt.signer.MetaRequest
	(*MetaResponse)(nil),          // 1: jwt.signer.MetaResponse
	(*SignRequest)(nil),           // 2: jwt.signer.SignRequest
	(*SignResponse)(nil),          // 3: jwt.signer.SignResponse
	(*jwt_pb.ResponseStatus)(nil), // 4: jwt.ResponseStatus
	(*jwt_pb.SignerMeta)(nil),     // 5: jwt.SignerMeta
	(*jwt_pb.Token)(nil),          // 6: jwt.Token
}
var file_pbschema_jwtsigner_proto_depIdxs = []int32{
	4, // 0: jwt.signer.MetaResponse.status:type_name -> jwt.ResponseStatus
	5, // 1: jwt.signer.MetaResponse.data:type_name -> jwt.SignerMeta
	4, // 2: jwt.signer.SignResponse.status:type_name -> jwt.ResponseStatus
	6, // 3: jwt.signer.SignResponse.token:type_name -> jwt.Token
	0, // 4: jwt.signer.JwtService.Meta:input_type -> jwt.signer.MetaRequest
	2, // 5: jwt.signer.JwtService.Sign:input_type -> jwt.signer.SignRequest
	1, // 6: jwt.signer.JwtService.Meta:output_type -> jwt.signer.MetaResponse
	3, // 7: jwt.signer.JwtService.Sign:output_type -> jwt.signer.SignResponse
	6, // [6:8] is the sub-list for method output_type
	4, // [4:6] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_pbschema_jwtsigner_proto_init() }
func file_pbschema_jwtsigner_proto_init() {
	if File_pbschema_jwtsigner_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pbschema_jwtsigner_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MetaRequest); i {
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
		file_pbschema_jwtsigner_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MetaResponse); i {
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
		file_pbschema_jwtsigner_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignRequest); i {
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
		file_pbschema_jwtsigner_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignResponse); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pbschema_jwtsigner_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_pbschema_jwtsigner_proto_goTypes,
		DependencyIndexes: file_pbschema_jwtsigner_proto_depIdxs,
		MessageInfos:      file_pbschema_jwtsigner_proto_msgTypes,
	}.Build()
	File_pbschema_jwtsigner_proto = out.File
	file_pbschema_jwtsigner_proto_rawDesc = nil
	file_pbschema_jwtsigner_proto_goTypes = nil
	file_pbschema_jwtsigner_proto_depIdxs = nil
}
