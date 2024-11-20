// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: penumbra/core/component/community_pool/v1/community_pool.proto

package community_poolv1

import (
	context "context"
	fmt "fmt"
	grpc1 "github.com/cosmos/gogoproto/grpc"
	proto "github.com/cosmos/gogoproto/proto"
	v1 "github.com/strangelove-ventures/interchaintest/v8/chain/penumbra/core/asset/v1"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// CommunityPool parameter data.
type CommunityPoolParameters struct {
	// Whether Community Pool spend proposals are enabled.
	CommunityPoolSpendProposalsEnabled bool `protobuf:"varint,1,opt,name=community_pool_spend_proposals_enabled,json=communityPoolSpendProposalsEnabled,proto3" json:"community_pool_spend_proposals_enabled,omitempty"`
}

func (m *CommunityPoolParameters) Reset()         { *m = CommunityPoolParameters{} }
func (m *CommunityPoolParameters) String() string { return proto.CompactTextString(m) }
func (*CommunityPoolParameters) ProtoMessage()    {}
func (*CommunityPoolParameters) Descriptor() ([]byte, []int) {
	return fileDescriptor_1c6b5a43fb54145e, []int{0}
}
func (m *CommunityPoolParameters) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CommunityPoolParameters) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CommunityPoolParameters.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CommunityPoolParameters) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CommunityPoolParameters.Merge(m, src)
}
func (m *CommunityPoolParameters) XXX_Size() int {
	return m.Size()
}
func (m *CommunityPoolParameters) XXX_DiscardUnknown() {
	xxx_messageInfo_CommunityPoolParameters.DiscardUnknown(m)
}

var xxx_messageInfo_CommunityPoolParameters proto.InternalMessageInfo

func (m *CommunityPoolParameters) GetCommunityPoolSpendProposalsEnabled() bool {
	if m != nil {
		return m.CommunityPoolSpendProposalsEnabled
	}
	return false
}

// CommunityPool genesis state.
type GenesisContent struct {
	// CommunityPool parameters.
	CommunityPoolParams *CommunityPoolParameters `protobuf:"bytes,1,opt,name=community_pool_params,json=communityPoolParams,proto3" json:"community_pool_params,omitempty"`
	// The initial balance of the Community Pool.
	InitialBalance *v1.Value `protobuf:"bytes,2,opt,name=initial_balance,json=initialBalance,proto3" json:"initial_balance,omitempty"`
}

func (m *GenesisContent) Reset()         { *m = GenesisContent{} }
func (m *GenesisContent) String() string { return proto.CompactTextString(m) }
func (*GenesisContent) ProtoMessage()    {}
func (*GenesisContent) Descriptor() ([]byte, []int) {
	return fileDescriptor_1c6b5a43fb54145e, []int{1}
}
func (m *GenesisContent) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *GenesisContent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_GenesisContent.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *GenesisContent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GenesisContent.Merge(m, src)
}
func (m *GenesisContent) XXX_Size() int {
	return m.Size()
}
func (m *GenesisContent) XXX_DiscardUnknown() {
	xxx_messageInfo_GenesisContent.DiscardUnknown(m)
}

var xxx_messageInfo_GenesisContent proto.InternalMessageInfo

func (m *GenesisContent) GetCommunityPoolParams() *CommunityPoolParameters {
	if m != nil {
		return m.CommunityPoolParams
	}
	return nil
}

func (m *GenesisContent) GetInitialBalance() *v1.Value {
	if m != nil {
		return m.InitialBalance
	}
	return nil
}

// Requests the list of all asset balances associated with the Community Pool.
type CommunityPoolAssetBalancesRequest struct {
	// (Optional): The specific asset balances to retrieve, if excluded all will be returned.
	AssetIds []*v1.AssetId `protobuf:"bytes,2,rep,name=asset_ids,json=assetIds,proto3" json:"asset_ids,omitempty"`
}

func (m *CommunityPoolAssetBalancesRequest) Reset()         { *m = CommunityPoolAssetBalancesRequest{} }
func (m *CommunityPoolAssetBalancesRequest) String() string { return proto.CompactTextString(m) }
func (*CommunityPoolAssetBalancesRequest) ProtoMessage()    {}
func (*CommunityPoolAssetBalancesRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_1c6b5a43fb54145e, []int{2}
}
func (m *CommunityPoolAssetBalancesRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CommunityPoolAssetBalancesRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CommunityPoolAssetBalancesRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CommunityPoolAssetBalancesRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CommunityPoolAssetBalancesRequest.Merge(m, src)
}
func (m *CommunityPoolAssetBalancesRequest) XXX_Size() int {
	return m.Size()
}
func (m *CommunityPoolAssetBalancesRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CommunityPoolAssetBalancesRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CommunityPoolAssetBalancesRequest proto.InternalMessageInfo

func (m *CommunityPoolAssetBalancesRequest) GetAssetIds() []*v1.AssetId {
	if m != nil {
		return m.AssetIds
	}
	return nil
}

// The Community Pool's balance of a single asset.
type CommunityPoolAssetBalancesResponse struct {
	// The balance for a single asset.
	Balance *v1.Value `protobuf:"bytes,1,opt,name=balance,proto3" json:"balance,omitempty"`
}

func (m *CommunityPoolAssetBalancesResponse) Reset()         { *m = CommunityPoolAssetBalancesResponse{} }
func (m *CommunityPoolAssetBalancesResponse) String() string { return proto.CompactTextString(m) }
func (*CommunityPoolAssetBalancesResponse) ProtoMessage()    {}
func (*CommunityPoolAssetBalancesResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_1c6b5a43fb54145e, []int{3}
}
func (m *CommunityPoolAssetBalancesResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CommunityPoolAssetBalancesResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CommunityPoolAssetBalancesResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CommunityPoolAssetBalancesResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CommunityPoolAssetBalancesResponse.Merge(m, src)
}
func (m *CommunityPoolAssetBalancesResponse) XXX_Size() int {
	return m.Size()
}
func (m *CommunityPoolAssetBalancesResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CommunityPoolAssetBalancesResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CommunityPoolAssetBalancesResponse proto.InternalMessageInfo

func (m *CommunityPoolAssetBalancesResponse) GetBalance() *v1.Value {
	if m != nil {
		return m.Balance
	}
	return nil
}

func init() {
	proto.RegisterType((*CommunityPoolParameters)(nil), "penumbra.core.component.community_pool.v1.CommunityPoolParameters")
	proto.RegisterType((*GenesisContent)(nil), "penumbra.core.component.community_pool.v1.GenesisContent")
	proto.RegisterType((*CommunityPoolAssetBalancesRequest)(nil), "penumbra.core.component.community_pool.v1.CommunityPoolAssetBalancesRequest")
	proto.RegisterType((*CommunityPoolAssetBalancesResponse)(nil), "penumbra.core.component.community_pool.v1.CommunityPoolAssetBalancesResponse")
}

func init() {
	proto.RegisterFile("penumbra/core/component/community_pool/v1/community_pool.proto", fileDescriptor_1c6b5a43fb54145e)
}

var fileDescriptor_1c6b5a43fb54145e = []byte{
	// 540 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x94, 0xc1, 0x8a, 0xd3, 0x40,
	0x18, 0xc7, 0x3b, 0x59, 0xd1, 0x75, 0x56, 0x56, 0x88, 0x88, 0xa5, 0x60, 0x5c, 0x73, 0x90, 0x0a,
	0x6e, 0x62, 0xaa, 0xa0, 0x54, 0x11, 0x6c, 0xd0, 0x45, 0x70, 0x21, 0x66, 0xa1, 0x07, 0xa9, 0x84,
	0x69, 0xf2, 0xb1, 0x1b, 0x48, 0x66, 0xe2, 0xcc, 0x24, 0xb0, 0x6f, 0xe1, 0xc1, 0x27, 0xf0, 0xe8,
	0x2b, 0xf8, 0x02, 0x22, 0x1e, 0x7a, 0xf4, 0x28, 0xed, 0xcd, 0xa7, 0x90, 0x49, 0x9a, 0xae, 0xa9,
	0x56, 0x82, 0x78, 0x69, 0xbf, 0xce, 0xfc, 0xfe, 0xff, 0xff, 0xf7, 0x4d, 0x33, 0xc1, 0x4f, 0x32,
	0xa0, 0x79, 0x3a, 0xe5, 0xc4, 0x0e, 0x19, 0x07, 0x3b, 0x64, 0x69, 0xc6, 0x28, 0x50, 0xa9, 0xaa,
	0x34, 0xa7, 0xb1, 0x3c, 0x0d, 0x32, 0xc6, 0x12, 0xbb, 0x70, 0xd6, 0x56, 0xac, 0x8c, 0x33, 0xc9,
	0xf4, 0xdb, 0xb5, 0xde, 0x52, 0x7a, 0x6b, 0xa5, 0xb7, 0xd6, 0xe8, 0xc2, 0xe9, 0x99, 0xcd, 0x28,
	0x22, 0x04, 0x48, 0xe5, 0x5b, 0x16, 0x95, 0x9d, 0x99, 0xe2, 0x6b, 0x6e, 0x2d, 0xf4, 0x18, 0x4b,
	0x3c, 0xc2, 0x49, 0x0a, 0x12, 0xb8, 0xd0, 0x7d, 0x7c, 0xab, 0xe9, 0x19, 0x88, 0x0c, 0x68, 0x14,
	0x64, 0x9c, 0x65, 0x4c, 0x90, 0x44, 0x04, 0x40, 0xc9, 0x34, 0x81, 0xa8, 0x8b, 0xf6, 0x50, 0x7f,
	0xdb, 0x37, 0xc3, 0x5f, 0x8d, 0x8e, 0x14, 0xeb, 0xd5, 0xe8, 0xb3, 0x8a, 0x34, 0x67, 0x08, 0xef,
	0x1e, 0x00, 0x05, 0x11, 0x0b, 0x97, 0x51, 0x09, 0x54, 0xea, 0x05, 0xbe, 0xba, 0x16, 0x93, 0xa9,
	0x1e, 0x44, 0xe9, 0xba, 0x33, 0x18, 0x59, 0xad, 0x07, 0xb6, 0x36, 0x4c, 0xe2, 0x5f, 0x09, 0x7f,
	0xdb, 0x10, 0xfa, 0x73, 0x7c, 0x39, 0xa6, 0xb1, 0x8c, 0x49, 0x12, 0x4c, 0x49, 0x42, 0x68, 0x08,
	0x5d, 0xad, 0x4c, 0xbc, 0xbe, 0x96, 0x58, 0x1d, 0x57, 0xe1, 0x58, 0x63, 0x92, 0xe4, 0xe0, 0xef,
	0x2e, 0x55, 0xa3, 0x4a, 0x64, 0x12, 0x7c, 0xb3, 0x91, 0xfb, 0x54, 0xe1, 0xcb, 0x4d, 0xe1, 0xc3,
	0xdb, 0x1c, 0x84, 0xd4, 0x1f, 0xe3, 0x8b, 0xa5, 0x4d, 0x10, 0x47, 0xa2, 0xab, 0xed, 0x6d, 0xf5,
	0x77, 0x06, 0x37, 0x36, 0xc5, 0x94, 0x06, 0x2f, 0x22, 0x7f, 0x9b, 0x54, 0x85, 0x30, 0xdf, 0x60,
	0xf3, 0x6f, 0x11, 0x22, 0x63, 0x54, 0x80, 0xfe, 0x00, 0x5f, 0xa8, 0x07, 0x41, 0x6d, 0x06, 0xa9,
	0xe9, 0xc1, 0x57, 0x84, 0x2f, 0xbd, 0xca, 0x81, 0x9f, 0x1e, 0x01, 0x2f, 0xe2, 0x10, 0xf4, 0x4f,
	0x08, 0xf7, 0x36, 0x07, 0xea, 0x2f, 0xff, 0xf5, 0x2f, 0xf9, 0xd3, 0xd1, 0xf4, 0x0e, 0xff, 0x93,
	0x5b, 0x75, 0x0a, 0x77, 0xd1, 0xe8, 0xfd, 0xd6, 0xe7, 0xb9, 0x81, 0x66, 0x73, 0x03, 0x7d, 0x9f,
	0x1b, 0xe8, 0xdd, 0xc2, 0xe8, 0xcc, 0x16, 0x46, 0xe7, 0xdb, 0xc2, 0xe8, 0xe0, 0xfd, 0x90, 0xa5,
	0xed, 0xe3, 0x46, 0x7a, 0xf3, 0x81, 0x52, 0x17, 0xc6, 0x43, 0xaf, 0xf9, 0x71, 0x2c, 0x4f, 0xf2,
	0xa9, 0xe2, 0x6d, 0x21, 0x39, 0xa1, 0xc7, 0x90, 0xb0, 0x02, 0xf6, 0x0b, 0xa0, 0x32, 0xe7, 0x20,
	0xec, 0x98, 0x4a, 0xe0, 0xe1, 0x09, 0x51, 0xdf, 0x42, 0xda, 0xc5, 0x43, 0xbb, 0xfc, 0x61, 0xb7,
	0xbe, 0xf9, 0x8f, 0x9a, 0x2b, 0x85, 0xf3, 0x41, 0x3b, 0xe7, 0xb9, 0xae, 0xfb, 0x51, 0xeb, 0x7b,
	0x75, 0xf3, 0xae, 0x6a, 0xde, 0x5d, 0x35, 0xdf, 0xe8, 0xd4, 0x1a, 0x3b, 0x5f, 0xce, 0xd0, 0x89,
	0x42, 0x27, 0x2b, 0x74, 0xd2, 0x40, 0x27, 0x63, 0x67, 0xae, 0xdd, 0x6f, 0x8b, 0x4e, 0x0e, 0xbc,
	0xd1, 0x21, 0x48, 0x12, 0x11, 0x49, 0x7e, 0x68, 0x77, 0x6a, 0xd9, 0x70, 0xa8, 0x74, 0xea, 0x73,
	0x29, 0x2c, 0xcb, 0x33, 0xe5, 0x70, 0x38, 0x76, 0xa6, 0xe7, 0xcb, 0x17, 0xce, 0xbd, 0x9f, 0x01,
	0x00, 0x00, 0xff, 0xff, 0x76, 0x42, 0xd5, 0x27, 0x01, 0x05, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// QueryServiceClient is the client API for QueryService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type QueryServiceClient interface {
	CommunityPoolAssetBalances(ctx context.Context, in *CommunityPoolAssetBalancesRequest, opts ...grpc.CallOption) (QueryService_CommunityPoolAssetBalancesClient, error)
}

type queryServiceClient struct {
	cc grpc1.ClientConn
}

func NewQueryServiceClient(cc grpc1.ClientConn) QueryServiceClient {
	return &queryServiceClient{cc}
}

func (c *queryServiceClient) CommunityPoolAssetBalances(ctx context.Context, in *CommunityPoolAssetBalancesRequest, opts ...grpc.CallOption) (QueryService_CommunityPoolAssetBalancesClient, error) {
	stream, err := c.cc.NewStream(ctx, &_QueryService_serviceDesc.Streams[0], "/penumbra.core.component.community_pool.v1.QueryService/CommunityPoolAssetBalances", opts...)
	if err != nil {
		return nil, err
	}
	x := &queryServiceCommunityPoolAssetBalancesClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type QueryService_CommunityPoolAssetBalancesClient interface {
	Recv() (*CommunityPoolAssetBalancesResponse, error)
	grpc.ClientStream
}

type queryServiceCommunityPoolAssetBalancesClient struct {
	grpc.ClientStream
}

func (x *queryServiceCommunityPoolAssetBalancesClient) Recv() (*CommunityPoolAssetBalancesResponse, error) {
	m := new(CommunityPoolAssetBalancesResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// QueryServiceServer is the server API for QueryService service.
type QueryServiceServer interface {
	CommunityPoolAssetBalances(*CommunityPoolAssetBalancesRequest, QueryService_CommunityPoolAssetBalancesServer) error
}

// UnimplementedQueryServiceServer can be embedded to have forward compatible implementations.
type UnimplementedQueryServiceServer struct {
}

func (*UnimplementedQueryServiceServer) CommunityPoolAssetBalances(req *CommunityPoolAssetBalancesRequest, srv QueryService_CommunityPoolAssetBalancesServer) error {
	return status.Errorf(codes.Unimplemented, "method CommunityPoolAssetBalances not implemented")
}

func RegisterQueryServiceServer(s grpc1.Server, srv QueryServiceServer) {
	s.RegisterService(&_QueryService_serviceDesc, srv)
}

func _QueryService_CommunityPoolAssetBalances_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(CommunityPoolAssetBalancesRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(QueryServiceServer).CommunityPoolAssetBalances(m, &queryServiceCommunityPoolAssetBalancesServer{stream})
}

type QueryService_CommunityPoolAssetBalancesServer interface {
	Send(*CommunityPoolAssetBalancesResponse) error
	grpc.ServerStream
}

type queryServiceCommunityPoolAssetBalancesServer struct {
	grpc.ServerStream
}

func (x *queryServiceCommunityPoolAssetBalancesServer) Send(m *CommunityPoolAssetBalancesResponse) error {
	return x.ServerStream.SendMsg(m)
}

var _QueryService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "penumbra.core.component.community_pool.v1.QueryService",
	HandlerType: (*QueryServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "CommunityPoolAssetBalances",
			Handler:       _QueryService_CommunityPoolAssetBalances_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "penumbra/core/component/community_pool/v1/community_pool.proto",
}

func (m *CommunityPoolParameters) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CommunityPoolParameters) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CommunityPoolParameters) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.CommunityPoolSpendProposalsEnabled {
		i--
		if m.CommunityPoolSpendProposalsEnabled {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *GenesisContent) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *GenesisContent) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *GenesisContent) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.InitialBalance != nil {
		{
			size, err := m.InitialBalance.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintCommunityPool(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.CommunityPoolParams != nil {
		{
			size, err := m.CommunityPoolParams.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintCommunityPool(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *CommunityPoolAssetBalancesRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CommunityPoolAssetBalancesRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CommunityPoolAssetBalancesRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.AssetIds) > 0 {
		for iNdEx := len(m.AssetIds) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.AssetIds[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintCommunityPool(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x12
		}
	}
	return len(dAtA) - i, nil
}

func (m *CommunityPoolAssetBalancesResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CommunityPoolAssetBalancesResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CommunityPoolAssetBalancesResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Balance != nil {
		{
			size, err := m.Balance.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintCommunityPool(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintCommunityPool(dAtA []byte, offset int, v uint64) int {
	offset -= sovCommunityPool(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *CommunityPoolParameters) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.CommunityPoolSpendProposalsEnabled {
		n += 2
	}
	return n
}

func (m *GenesisContent) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.CommunityPoolParams != nil {
		l = m.CommunityPoolParams.Size()
		n += 1 + l + sovCommunityPool(uint64(l))
	}
	if m.InitialBalance != nil {
		l = m.InitialBalance.Size()
		n += 1 + l + sovCommunityPool(uint64(l))
	}
	return n
}

func (m *CommunityPoolAssetBalancesRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.AssetIds) > 0 {
		for _, e := range m.AssetIds {
			l = e.Size()
			n += 1 + l + sovCommunityPool(uint64(l))
		}
	}
	return n
}

func (m *CommunityPoolAssetBalancesResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Balance != nil {
		l = m.Balance.Size()
		n += 1 + l + sovCommunityPool(uint64(l))
	}
	return n
}

func sovCommunityPool(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozCommunityPool(x uint64) (n int) {
	return sovCommunityPool(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *CommunityPoolParameters) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCommunityPool
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: CommunityPoolParameters: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CommunityPoolParameters: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field CommunityPoolSpendProposalsEnabled", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCommunityPool
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.CommunityPoolSpendProposalsEnabled = bool(v != 0)
		default:
			iNdEx = preIndex
			skippy, err := skipCommunityPool(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthCommunityPool
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *GenesisContent) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCommunityPool
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: GenesisContent: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: GenesisContent: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CommunityPoolParams", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCommunityPool
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthCommunityPool
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthCommunityPool
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.CommunityPoolParams == nil {
				m.CommunityPoolParams = &CommunityPoolParameters{}
			}
			if err := m.CommunityPoolParams.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field InitialBalance", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCommunityPool
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthCommunityPool
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthCommunityPool
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.InitialBalance == nil {
				m.InitialBalance = &v1.Value{}
			}
			if err := m.InitialBalance.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCommunityPool(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthCommunityPool
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *CommunityPoolAssetBalancesRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCommunityPool
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: CommunityPoolAssetBalancesRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CommunityPoolAssetBalancesRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AssetIds", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCommunityPool
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthCommunityPool
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthCommunityPool
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AssetIds = append(m.AssetIds, &v1.AssetId{})
			if err := m.AssetIds[len(m.AssetIds)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCommunityPool(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthCommunityPool
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *CommunityPoolAssetBalancesResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCommunityPool
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: CommunityPoolAssetBalancesResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CommunityPoolAssetBalancesResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Balance", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCommunityPool
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthCommunityPool
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthCommunityPool
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Balance == nil {
				m.Balance = &v1.Value{}
			}
			if err := m.Balance.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCommunityPool(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthCommunityPool
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipCommunityPool(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowCommunityPool
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowCommunityPool
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowCommunityPool
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthCommunityPool
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupCommunityPool
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthCommunityPool
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthCommunityPool        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowCommunityPool          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupCommunityPool = fmt.Errorf("proto: unexpected end of group")
)
