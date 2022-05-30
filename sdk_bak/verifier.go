package sdk

import (
	"errors"
	"strings"

	"github.com/Golang-Tools/jwthelper/v2/exceptions"
	"github.com/Golang-Tools/jwthelper/v2/jwt_pb"
	"github.com/Golang-Tools/jwthelper/v2/jwtverifier_pb"
	"github.com/Golang-Tools/jwthelper/v2/verifyoptions"
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
func (c *Verifier) Verify(token *jwt_pb.Token, payload interface{}, opts ...verifyoptions.VerifyOption) (*jwt_pb.JwtStatus, error) {
	var jwt_status *jwt_pb.JwtStatus
	defaultopt := verifyoptions.VerifyOptions{}
	for _, opt := range opts {
		opt.Apply(&defaultopt)
	}
	query := jwtverifier_pb.VerifyRequest{
		Token:                   token,
		CheckMatchSub:           defaultopt.CheckMatchSUB,
		CheckMatchallAud:        defaultopt.CheckMatchALLAUD,
		CheckMatchanyAud:        defaultopt.CheckMatchAnyAUD,
		CheckNotmatchAud:        defaultopt.CheckNotMatchAUD,
		CheckMatchIss:           defaultopt.CheckMatchISS,
		NotCheckRefreshTokenAud: defaultopt.NotCheckRefreshTokenAUD,
		NotCheckRefreshTokenJti: defaultopt.NotCheckRefreshTokenJTI,
	}
	ctx, cancel := c.sdk.NewCtx()
	defer cancel()
	res, err := c.rpc.Verify(ctx, &query)
	if res != nil {
		if res.Payload != nil && string(res.Payload) != "" {
			err := json.Unmarshal(res.Payload, payload)
			if err != nil {
				return nil, err
			}
		}
		if res.JwtStatus != nil || res.JwtStatus.Jti != "" {
			jwt_status = res.JwtStatus
		} else {
			jwt_status = nil
		}
	}
	if err == nil {
		if res.Status == nil || res.Status.Status == jwt_pb.ResponseStatus_FAILED {
			var err error
			if res.Status.Message != "" {
				err = errors.New(res.Status.Message)
			} else {
				err = ErrRpcResponseError
			}
			return jwt_status, err
		} else {
			return jwt_status, nil
		}
	} else {
		errmsg := err.Error()
		switch {
		case strings.Contains(errmsg, exceptions.ErrValidationErrorExpired.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorExpired
			}
		case strings.Contains(errmsg, exceptions.ErrAccessTokenNotFound.Error()):
			{
				return jwt_status, exceptions.ErrAccessTokenNotFound
			}
		case strings.Contains(errmsg, exceptions.ErrSignWithRefreshTokenNeedSUB.Error()):
			{
				return jwt_status, exceptions.ErrSignWithRefreshTokenNeedSUB
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorUnknown.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorUnknown
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorMalformed.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorMalformed
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorUnverifiable.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorUnverifiable
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorSignatureInvalid.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorSignatureInvalid
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorAudience.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorAudience
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorSubject.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorSubject
			}

		case strings.Contains(errmsg, exceptions.ErrValidationErrorIssuedAt.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorIssuedAt
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorIssuer.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorIssuer
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorNotValidYet.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorNotValidYet
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorId.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorId
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorClaimsInvalid.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorClaimsInvalid
			}
		case strings.Contains(errmsg, exceptions.ErrValidationErrorCanNotHandle.Error()):
			{
				return jwt_status, exceptions.ErrValidationErrorCanNotHandle
			}
		case strings.Contains(errmsg, exceptions.ErrRefreshTokenSUBNotMatch.Error()):
			{
				return jwt_status, exceptions.ErrRefreshTokenSUBNotMatch
			}
		case strings.Contains(errmsg, exceptions.ErrRefreshTokenAudNotMatch.Error()):
			{
				return jwt_status, exceptions.ErrRefreshTokenAudNotMatch
			}
		case strings.Contains(errmsg, exceptions.ErrRefreshTokenJtiNotMatch.Error()):
			{
				return jwt_status, exceptions.ErrRefreshTokenJtiNotMatch
			}
		case strings.Contains(errmsg, exceptions.ErrRefreshTokenIssNotInRange.Error()):
			{
				return jwt_status, exceptions.ErrRefreshTokenIssNotInRange
			}
		case strings.Contains(errmsg, exceptions.ErrRefreshTokenNotHaveEXP.Error()):
			{
				return jwt_status, exceptions.ErrRefreshTokenNotHaveEXP
			}
		case strings.Contains(errmsg, exceptions.ErrRefreshTokenValidationError.Error()):
			{
				return jwt_status, exceptions.ErrRefreshTokenValidationError
			}
		case strings.Contains(errmsg, exceptions.ErrRefreshTokenParseError.Error()):
			{
				return jwt_status, exceptions.ErrRefreshTokenParseError
			}
		default:
			{
				return jwt_status, err
			}
		}
	}
}

//Close 断开连接
func (c *Verifier) Close() error {
	return c.conn.Close()
}
