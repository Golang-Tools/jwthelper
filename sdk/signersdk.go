package sdk

import (
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/Golang-Tools/grpcsdk/v2"
	"github.com/Golang-Tools/jwthelper/v4/jwt_pb"
	"github.com/Golang-Tools/jwthelper/v4/jwtsigner_pb"
	"github.com/Golang-Tools/jwthelper/v4/signoptions"
	"github.com/Golang-Tools/optparams"
)

type SignerSDK struct {
	client *grpcsdk.SDK[jwtsigner_pb.JwtsignerClient]
}

func NewSignerSDK() *SignerSDK {
	s := new(SignerSDK)
	s.client = grpcsdk.New(jwtsigner_pb.NewJwtsignerClient, &jwtsigner_pb.Jwtsigner_ServiceDesc)
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
func (c *SignerSDK) Meta() (*jwt_pb.SignerMeta, error) {
	ctx, cancel := c.client.NewCtx()
	defer cancel()
	Conn, release := c.client.GetClient()
	defer release()
	res, err := Conn.Meta(ctx, &jwtsigner_pb.MetaRequest{})
	if err != nil {
		return nil, err
	}
	if res.Status == nil {
		return nil, ErrRpcResponseError
	}
	if res.Status.Status == jwt_pb.ResponseStatus_FAILED {
		if res.Status.Message != "" {
			return nil, errors.New(res.Status.Message)
		}
		return nil, ErrRpcResponseError
	}
	return res.Data, nil
}

// Sign 签名一个token
func (c *SignerSDK) Sign(payload interface{}, opts ...optparams.Option[signoptions.SignOptions]) (*jwt_pb.Token, error) {
	if payload == nil {
		payload = map[string]interface{}{}
	}
	payloadb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	defaultopt := optparams.GetOption(&signoptions.DefaultSignOptions, opts...)
	query := jwtsigner_pb.SignRequest{
		Sub:        defaultopt.Sub,
		Exp:        defaultopt.Exp,
		Nbf:        defaultopt.Nbf,
		Refreshexp: defaultopt.RefreshExp,
		Payload:    payloadb,
		Jti:        defaultopt.Jti,
		Aud:        defaultopt.Aud,
	}
	ctx, cancel := c.client.NewCtx()
	defer cancel()
	Conn, release := c.client.GetClient()
	defer release()
	res, err := Conn.Sign(ctx, &query)
	if err != nil {
		return nil, err
	}
	if res.Status == nil {
		return nil, ErrRpcResponseError
	}
	if res.Status.Status == jwt_pb.ResponseStatus_FAILED {
		if res.Status.Message != "" {
			return nil, errors.New(res.Status.Message)
		}
		return nil, ErrRpcResponseError
	}
	return res.Token, nil
}

var DefaultSigner *SignerSDK

func init() {
	DefaultSigner = NewSignerSDK()
}
