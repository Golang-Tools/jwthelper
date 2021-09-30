package sdk

import (
	"errors"

	"github.com/Golang-Tools/jwthelper/jwt_pb"
	"github.com/Golang-Tools/jwthelper/jwtsigner_pb"
	"github.com/Golang-Tools/jwthelper/signoptions"
	"google.golang.org/grpc"
)

//NewSigner 建立一个新的签名器
func (c *SDK) NewSigner() (*Signer, error) {
	conn, err := newSigner(c, c.addr, c.opts...)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

//Signer 客户端类
type Signer struct {
	rpc  jwtsigner_pb.JwtsignerClient
	conn *grpc.ClientConn
	sdk  *SDK
}

func newSigner(sdk *SDK, addr string, opts ...grpc.DialOption) (*Signer, error) {
	c := new(Signer)
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}
	c.sdk = sdk
	c.conn = conn
	c.rpc = jwtsigner_pb.NewJwtsignerClient(conn)
	return c, nil
}

//Meta 查看远端签名器的元信息
func (c *Signer) Meta() (*jwt_pb.SignerMeta, error) {
	ctx, cancel := c.sdk.NewCtx()
	defer cancel()
	res, err := c.rpc.Meta(ctx, &jwtsigner_pb.MetaRequest{})
	if err != nil {
		return nil, err
	}
	if res.Status == nil || res.Status.Status == jwt_pb.ResponseStatus_FAILED {
		var err error
		if res.Status.Message != "" {
			err = errors.New(res.Status.Message)
		} else {
			err = ErrRpcResponseError
		}
		return nil, err
	}
	return res.Data, nil
}

// Sign 签名一个token
func (c *Signer) Sign(payload interface{}, opts ...signoptions.SignOption) (*jwt_pb.Token, error) {
	if payload == nil {
		payload = map[string]interface{}{}
	}
	payloadb, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	defaultopt := signoptions.DefaultSignOptions
	for _, opt := range opts {
		opt.Apply(&defaultopt)
	}
	query := jwtsigner_pb.SignRequest{
		Sub:        defaultopt.Sub,
		Exp:        defaultopt.Exp,
		Nbf:        defaultopt.Nbf,
		Refreshexp: defaultopt.RefreshExp,
		Payload:    payloadb,
		Jti:        defaultopt.Jti,
		Aud:        defaultopt.Aud,
	}
	ctx, cancel := c.sdk.NewCtx()
	defer cancel()
	res, err := c.rpc.Sign(ctx, &query)
	if err != nil {
		return nil, err
	}
	if res.Status == nil || res.Status.Status == jwt_pb.ResponseStatus_FAILED {
		var err error
		if res.Status.Message != "" {
			err = errors.New(res.Status.Message)
		} else {
			err = ErrRpcResponseError
		}
		return nil, err
	}
	return res.Token, nil
}

//Close 断开连接
func (c *Signer) Close() error {
	return c.conn.Close()
}
