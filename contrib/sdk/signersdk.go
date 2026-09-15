package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/Golang-Tools/grpcsdk/v2"
	"github.com/Golang-Tools/jwthelper/contrib/pb/jwtpb"
	"github.com/Golang-Tools/jwthelper/contrib/pb/pbconv"
	"github.com/Golang-Tools/jwthelper/contrib/pb/signerpb"
	jwthelper "github.com/Golang-Tools/jwthelper/v4"
	"github.com/Golang-Tools/jwthelper/v4/exceptions"
	"github.com/Golang-Tools/jwthelper/v4/signoptions"
	"github.com/Golang-Tools/optparams"
)

type SignerSDK struct {
	client *grpcsdk.SDK[signerpb.JwtsignerClient]
}

func NewSignerSDK() *SignerSDK {
	s := new(SignerSDK)
	s.client = grpcsdk.New(signerpb.NewJwtsignerClient, &signerpb.Jwtsigner_ServiceDesc)
	return s
}

func (s *SignerSDK) Init(opts ...optparams.Option[grpcsdk.SDKConfig]) error {
	return s.client.Init(opts...)
}

func (s *SignerSDK) GetLogger() *slog.Logger {
	return s.client.Logger
}

// Close 断开连接
func (c *SignerSDK) Close() error {
	return c.client.Close()
}

// Meta 查看远端签名器的元信息
// ctx 为nil时使用SDK配置的默认超时上下文
func (c *SignerSDK) Meta(ctx context.Context) (*jwthelper.SignerMeta, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = c.client.NewCtx()
		defer cancel()
	}
	Conn, release := c.client.GetClient()
	defer release()
	res, err := Conn.Meta(ctx, &signerpb.MetaRequest{})
	if err != nil {
		return nil, err
	}
	if res.Status == nil {
		return nil, ErrRpcResponseError
	}
	if res.Status.Status == jwtpb.ResponseStatus_FAILED {
		if sentinel := exceptions.SentinelByKind(res.Status.ErrorKind); sentinel != nil {
			return nil, sentinel
		}
		if res.Status.Message != "" {
			return nil, errors.New(res.Status.Message)
		}
		return nil, ErrRpcResponseError
	}
	return pbconv.SignerMetaFromPB(res.Data)
}

// Sign 签名一个token
// ctx 为nil时使用SDK配置的默认超时上下文
func (c *SignerSDK) Sign(ctx context.Context, payload interface{}, opts ...optparams.Option[signoptions.SignOptions]) (*jwthelper.Token, error) {
	if payload == nil {
		payload = map[string]interface{}{}
	}
	payloadb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	defaultopt := optparams.GetOption(&signoptions.DefaultSignOptions, opts...)
	query := signerpb.SignRequest{
		Sub:        defaultopt.Sub,
		Exp:        defaultopt.Exp,
		Nbf:        defaultopt.Nbf,
		Refreshexp: defaultopt.RefreshExp,
		Payload:    payloadb,
		Jti:        defaultopt.Jti,
		Aud:        defaultopt.Aud,
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = c.client.NewCtx()
		defer cancel()
	}
	Conn, release := c.client.GetClient()
	defer release()
	res, err := Conn.Sign(ctx, &query)
	if err != nil {
		if res != nil && res.Status != nil {
			if sentinel := exceptions.SentinelByKind(res.Status.ErrorKind); sentinel != nil {
				return nil, sentinel
			}
		}
		return nil, err
	}
	if res.Status == nil {
		return nil, ErrRpcResponseError
	}
	if res.Status.Status == jwtpb.ResponseStatus_FAILED {
		if sentinel := exceptions.SentinelByKind(res.Status.ErrorKind); sentinel != nil {
			return nil, sentinel
		}
		if res.Status.Message != "" {
			return nil, errors.New(res.Status.Message)
		}
		return nil, ErrRpcResponseError
	}
	return pbconv.TokenFromPB(res.Token), nil
}

var DefaultSigner *SignerSDK

func init() {
	DefaultSigner = NewSignerSDK()
}
