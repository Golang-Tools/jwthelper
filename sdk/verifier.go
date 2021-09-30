package sdk

import (
	"errors"
	"time"

	"github.com/Golang-Tools/jwthelper/jwt_pb"
	"github.com/Golang-Tools/jwthelper/jwtverifier_pb"
	"github.com/Golang-Tools/jwthelper/verifyoptions"
	"google.golang.org/grpc"
)

//NewVerifier 建立一个新的连接
func (c *SDK) NewVerifier() (*Verifier, error) {
	conn, err := newVerifier(c, c.addr, c.opts...)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

//Verifier 客户端类
type Verifier struct {
	rpc  jwtverifier_pb.JwtverifierClient
	conn *grpc.ClientConn
	sdk  *SDK
}

func newVerifier(sdk *SDK, addr string, opts ...grpc.DialOption) (*Verifier, error) {
	c := new(Verifier)
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}
	c.sdk = sdk
	c.conn = conn
	c.rpc = jwtverifier_pb.NewJwtverifierClient(conn)
	return c, nil
}

//Meta 查看远端签名器的元信息
func (c *Verifier) Meta() (*jwt_pb.VerifierMeta, error) {
	ctx, cancel := c.sdk.NewCtx()
	defer cancel()
	res, err := c.rpc.Meta(ctx, &jwtverifier_pb.MetaRequest{})
	if err != nil {
		return nil, err
	}
	if res.Data.DefaultISSRange == nil {
		res.Data.DefaultISSRange = []string{}
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

// Verify 签名一个token
func (c *Verifier) Verify(token *jwt_pb.Token, payload interface{}, opts ...verifyoptions.VerifyOption) (string, time.Duration, error) {
	defaultopt := verifyoptions.VerifyOptions{}
	for _, opt := range opts {
		opt.Apply(&defaultopt)
	}
	query := jwtverifier_pb.VerifyRequest{
		Token:                   token,
		CheckMatchSub:           defaultopt.CheckMatchSUB,
		CheckMatchAud:           defaultopt.CheckMatchAUD,
		CheckMatchIss:           defaultopt.CheckMatchISS,
		NotCheckRefreshTokenAud: defaultopt.NotCheckRefreshTokenAUD,
		NotCheckRefreshTokenJti: defaultopt.NotCheckRefreshTokenJTI,
	}
	ctx, cancel := c.sdk.NewCtx()
	defer cancel()
	res, err := c.rpc.Verify(ctx, &query)
	if err != nil {
		return "", 0, err
	}
	if res.Status == nil || res.Status.Status == jwt_pb.ResponseStatus_FAILED {
		var err error
		if res.Status.Message != "" {
			err = errors.New(res.Status.Message)
		} else {
			err = ErrRpcResponseError
		}
		return "", 0, err
	}
	jti := res.Jti
	timeleft := time.Duration(res.TimeLeft)
	err = json.Unmarshal(res.Payload, payload)
	if err != nil {
		return jti, timeleft, err
	}
	return jti, timeleft, nil
}

//Close 断开连接
func (c *Verifier) Close() error {
	return c.conn.Close()
}
