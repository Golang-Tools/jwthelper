package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/Golang-Tools/grpcsdk/v2"
	"github.com/Golang-Tools/jwthelper/contrib/pb/jwtpb"
	"github.com/Golang-Tools/jwthelper/contrib/pb/pbconv"
	"github.com/Golang-Tools/jwthelper/contrib/pb/verifierpb"
	jwthelper "github.com/Golang-Tools/jwthelper/v4"
	"github.com/Golang-Tools/jwthelper/v4/exceptions"
	"github.com/Golang-Tools/jwthelper/v4/verifyoptions"
	"github.com/Golang-Tools/optparams"
)

type VerifierSDK struct {
	client *grpcsdk.SDK[verifierpb.JwtverifierClient]
}

func NewVerifierSDK() *VerifierSDK {
	s := new(VerifierSDK)
	s.client = grpcsdk.New(verifierpb.NewJwtverifierClient, &verifierpb.Jwtverifier_ServiceDesc)
	return s
}

func (s *VerifierSDK) Init(opts ...optparams.Option[grpcsdk.SDKConfig]) error {
	return s.client.Init(opts...)
}

func (s *VerifierSDK) GetLogger() *slog.Logger {
	return s.client.Logger
}

// Close 断开连接
func (c *VerifierSDK) Close() error {
	return c.client.Close()
}

// Meta 查看远端签名器的元信息
// ctx 为nil时使用SDK配置的默认超时上下文
func (c *VerifierSDK) Meta(ctx context.Context) (*jwthelper.VerifierMeta, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = c.client.NewCtx()
		defer cancel()
	}
	Conn, release := c.client.GetClient()
	defer release()
	res, err := Conn.Meta(ctx, &verifierpb.MetaRequest{})
	if err != nil {
		return nil, err
	}
	if res.Status == nil {
		return nil, ErrRpcResponseError
	}
	if res.Status.Status == jwtpb.ResponseStatus_FAILED {
		if res.Status.Message != "" {
			return nil, errors.New(res.Status.Message)
		}
		return nil, ErrRpcResponseError
	}
	return pbconv.VerifierMetaFromPB(res.Data)
}

// Verify 校验一个token
// ctx 为nil时使用SDK配置的默认超时上下文
func (c *VerifierSDK) Verify(ctx context.Context, token *jwthelper.Token, payload interface{}, opts ...optparams.Option[verifyoptions.VerifyOptions]) (*jwthelper.JwtStatus, error) {
	var jwt_status *jwthelper.JwtStatus
	defaultopt := optparams.GetOption(new(verifyoptions.VerifyOptions), opts...)
	query := verifierpb.VerifyRequest{
		Token:                   pbconv.TokenToPB(token),
		CheckMatchSub:           defaultopt.CheckMatchSUB,
		CheckMatchallAud:        defaultopt.CheckMatchALLAUD,
		CheckMatchanyAud:        defaultopt.CheckMatchAnyAUD,
		CheckNotmatchAud:        defaultopt.CheckNotMatchAUD,
		CheckMatchIss:           defaultopt.CheckMatchISS,
		NotCheckRefreshTokenAud: defaultopt.NotCheckRefreshTokenAUD,
		NotCheckRefreshTokenJti: defaultopt.NotCheckRefreshTokenJTI,
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = c.client.NewCtx()
		defer cancel()
	}
	Conn, release := c.client.GetClient()
	defer release()
	res, err := Conn.Verify(ctx, &query)
	if err != nil {
		// 传输层错误:服务端未按协议应答或网络异常
		if res != nil && res.Status != nil {
			if sentinel := exceptions.SentinelByKind(res.Status.ErrorKind); sentinel != nil {
				return jwt_status, sentinel
			}
		}
		return jwt_status, err
	}
	if res == nil {
		return jwt_status, ErrRpcResponseError
	}
	if res.Payload != nil && string(res.Payload) != "" {
		if uerr := json.Unmarshal(res.Payload, payload); uerr != nil {
			return nil, uerr
		}
	}
	jwt_status = pbconv.JwtStatusFromPB(res.JwtStatus)
	if res.Status == nil {
		return jwt_status, ErrRpcResponseError
	}
	// 业务错误经error_kind映射(包括SUCCEED携带的过期提示)
	if sentinel := exceptions.SentinelByKind(res.Status.ErrorKind); sentinel != nil {
		return jwt_status, sentinel
	}
	if res.Status.Status == jwtpb.ResponseStatus_FAILED {
		if res.Status.Message != "" {
			return jwt_status, errors.New(res.Status.Message)
		}
		return jwt_status, ErrRpcResponseError
	}
	return jwt_status, nil
}

var DefaultVerifier *VerifierSDK

func init() {
	DefaultVerifier = NewVerifierSDK()
}
