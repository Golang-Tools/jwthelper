package sdk

import (
	"context"
	"net"
	"testing"

	"github.com/Golang-Tools/grpcsdk/v2"
	"github.com/Golang-Tools/jwthelper/contrib/pb/jwtpb"
	"github.com/Golang-Tools/jwthelper/contrib/pb/signerpb"
	"github.com/Golang-Tools/jwthelper/contrib/pb/verifierpb"
	jwthelper "github.com/Golang-Tools/jwthelper/v4"
	"github.com/Golang-Tools/jwthelper/v4/exceptions"
	"github.com/stretchr/testify/assert"
	grpc "google.golang.org/grpc"
)

// fakeSignerServer 伪签名服务端,用于验证SDK的请求/响应解析与错误映射
type fakeSignerServer struct {
	signerpb.UnimplementedJwtsignerServer
	failKind string
}

func (f *fakeSignerServer) Meta(ctx context.Context, in *signerpb.MetaRequest) (*signerpb.MetaResponse, error) {
	return &signerpb.MetaResponse{
		Status: &jwtpb.ResponseStatus{Status: jwtpb.ResponseStatus_SUCCEED},
		Data: &jwtpb.SignerMeta{
			Algo:       jwtpb.EncryptionAlgorithm_HS256,
			Iss:        "test-iss",
			DefaultTTL: 600,
			JtiGen:     "uuid4",
		},
	}, nil
}

func (f *fakeSignerServer) Sign(ctx context.Context, in *signerpb.SignRequest) (*signerpb.SignResponse, error) {
	if f.failKind != "" {
		return &signerpb.SignResponse{
			Status: &jwtpb.ResponseStatus{
				Status:    jwtpb.ResponseStatus_FAILED,
				Message:   "mock failure",
				ErrorKind: f.failKind,
			},
		}, nil
	}
	return &signerpb.SignResponse{
		Status: &jwtpb.ResponseStatus{Status: jwtpb.ResponseStatus_SUCCEED},
		Token:  &jwtpb.Token{AccessToken: "access", RefreshToken: "refresh"},
	}, nil
}

// fakeVerifierServer 伪校验服务端,用于验证SDK的请求/响应解析与错误映射
type fakeVerifierServer struct {
	verifierpb.UnimplementedJwtverifierServer
	failKind string
	expired  bool
}

func (f *fakeVerifierServer) Meta(ctx context.Context, in *verifierpb.MetaRequest) (*verifierpb.MetaResponse, error) {
	return &verifierpb.MetaResponse{
		Status: &jwtpb.ResponseStatus{Status: jwtpb.ResponseStatus_SUCCEED},
		Data:   &jwtpb.VerifierMeta{Algo: jwtpb.EncryptionAlgorithm_HS256, DefaultAUD: "aud"},
	}, nil
}

func (f *fakeVerifierServer) Verify(ctx context.Context, in *verifierpb.VerifyRequest) (*verifierpb.VerifyResponse, error) {
	status := &jwtpb.JwtStatus{Jti: "jti", Sub: "sub", Iss: "iss", TimeLeft: 100}
	payload := []byte(`{"a":1}`)
	if f.expired {
		return &verifierpb.VerifyResponse{
			Status: &jwtpb.ResponseStatus{
				Status:    jwtpb.ResponseStatus_SUCCEED,
				ErrorKind: "validation_expired",
			},
			JwtStatus: status,
			Payload:   payload,
		}, nil
	}
	if f.failKind != "" {
		return &verifierpb.VerifyResponse{
			Status: &jwtpb.ResponseStatus{
				Status:    jwtpb.ResponseStatus_FAILED,
				Message:   "mock failure",
				ErrorKind: f.failKind,
			},
			Payload: payload,
		}, nil
	}
	return &verifierpb.VerifyResponse{
		Status:    &jwtpb.ResponseStatus{Status: jwtpb.ResponseStatus_SUCCEED},
		JwtStatus: status,
		Payload:   payload,
	}, nil
}

// startTestServer 启动测试用grpc服务端,返回监听地址
func startTestServer(t *testing.T, register func(gs grpc.ServiceRegistrar)) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	register(gs)
	go func() {
		_ = gs.Serve(lis)
	}()
	t.Cleanup(func() { gs.Stop() })
	return lis.Addr().String()
}

// newTestSignerSDK 创建指向测试服务端的签名SDK
func newTestSignerSDK(t *testing.T, addr string) *SignerSDK {
	t.Helper()
	cli := NewSignerSDK()
	if err := cli.Init(grpcsdk.WithQueryAddresses(addr)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

// newTestVerifierSDK 创建指向测试服务端的校验SDK
func newTestVerifierSDK(t *testing.T, addr string) *VerifierSDK {
	t.Helper()
	cli := NewVerifierSDK()
	if err := cli.Init(grpcsdk.WithQueryAddresses(addr)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

// TestSignerSDKMeta 签名器Meta请求的解析
func TestSignerSDKMeta(t *testing.T) {
	fake := &fakeSignerServer{}
	addr := startTestServer(t, func(gs grpc.ServiceRegistrar) {
		signerpb.RegisterJwtsignerServer(gs, fake)
	})
	cli := newTestSignerSDK(t, addr)
	meta, err := cli.Meta(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, jwthelper.AlgoHS256, meta.Algo)
	assert.Equal(t, "test-iss", meta.Iss)
	assert.Equal(t, int64(600), meta.DefaultTTL)
	assert.Equal(t, "uuid4", meta.JtiGen)
}

// TestSignerSDKSign 签名请求的解析(核心类型Token)
func TestSignerSDKSign(t *testing.T) {
	fake := &fakeSignerServer{}
	addr := startTestServer(t, func(gs grpc.ServiceRegistrar) {
		signerpb.RegisterJwtsignerServer(gs, fake)
	})
	cli := newTestSignerSDK(t, addr)
	token, err := cli.Sign(context.Background(), map[string]interface{}{"a": 1})
	assert.NoError(t, err)
	assert.Equal(t, "access", token.AccessToken)
	assert.Equal(t, "refresh", token.RefreshToken)
}

// TestSignerSDKSignErrorKind 失败响应通过error_kind映射为哨兵错误
func TestSignerSDKSignErrorKind(t *testing.T) {
	fake := &fakeSignerServer{failKind: "sign_with_refresh_token_need_sub"}
	addr := startTestServer(t, func(gs grpc.ServiceRegistrar) {
		signerpb.RegisterJwtsignerServer(gs, fake)
	})
	cli := newTestSignerSDK(t, addr)
	_, err := cli.Sign(context.Background(), nil)
	assert.ErrorIs(t, err, exceptions.ErrSignWithRefreshTokenNeedSUB)
}

// TestVerifierSDKVerify 校验请求的解析(核心类型JwtStatus与payload)
func TestVerifierSDKVerify(t *testing.T) {
	fake := &fakeVerifierServer{}
	addr := startTestServer(t, func(gs grpc.ServiceRegistrar) {
		verifierpb.RegisterJwtverifierServer(gs, fake)
	})
	cli := newTestVerifierSDK(t, addr)
	payload := map[string]interface{}{}
	status, err := cli.Verify(context.Background(), &jwthelper.Token{AccessToken: "at"}, &payload)
	assert.NoError(t, err)
	assert.Equal(t, "jti", status.Jti)
	assert.Equal(t, int64(100), status.TimeLeft)
	assert.Equal(t, float64(1), payload["a"])
}

// TestVerifierSDKVerifyExpired 过期场景:应答携带校验状态,错误通过error_kind映射
func TestVerifierSDKVerifyExpired(t *testing.T) {
	fake := &fakeVerifierServer{expired: true}
	addr := startTestServer(t, func(gs grpc.ServiceRegistrar) {
		verifierpb.RegisterJwtverifierServer(gs, fake)
	})
	cli := newTestVerifierSDK(t, addr)
	payload := map[string]interface{}{}
	status, err := cli.Verify(context.Background(), &jwthelper.Token{AccessToken: "at"}, &payload)
	assert.ErrorIs(t, err, exceptions.ErrValidationErrorExpired)
	assert.NotNil(t, status)
	assert.Equal(t, "jti", status.Jti)
}

// TestVerifierSDKVerifyErrorKind 失败响应通过error_kind映射为哨兵错误
func TestVerifierSDKVerifyErrorKind(t *testing.T) {
	fake := &fakeVerifierServer{failKind: "refresh_token_sub_not_match"}
	addr := startTestServer(t, func(gs grpc.ServiceRegistrar) {
		verifierpb.RegisterJwtverifierServer(gs, fake)
	})
	cli := newTestVerifierSDK(t, addr)
	payload := map[string]interface{}{}
	_, err := cli.Verify(context.Background(), &jwthelper.Token{AccessToken: "at"}, &payload)
	assert.ErrorIs(t, err, exceptions.ErrRefreshTokenSUBNotMatch)
}

// TestVerifierSDKMeta 校验器Meta请求的解析
func TestVerifierSDKMeta(t *testing.T) {
	fake := &fakeVerifierServer{}
	addr := startTestServer(t, func(gs grpc.ServiceRegistrar) {
		verifierpb.RegisterJwtverifierServer(gs, fake)
	})
	cli := newTestVerifierSDK(t, addr)
	meta, err := cli.Meta(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, jwthelper.AlgoHS256, meta.Algo)
	assert.Equal(t, "aud", meta.DefaultAUD)
}
