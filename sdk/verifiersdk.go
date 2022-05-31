package sdk

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/Golang-Tools/grpcsdk"
	"github.com/Golang-Tools/jwthelper/v2/exceptions"
	"github.com/Golang-Tools/jwthelper/v2/jwt_pb"
	"github.com/Golang-Tools/jwthelper/v2/jwtverifier_pb"
	"github.com/Golang-Tools/jwthelper/v2/verifyoptions"
	"github.com/Golang-Tools/loggerhelper/v2"
	"github.com/Golang-Tools/optparams"
)

type VerifierSDK struct {
	client *grpcsdk.SDK[jwtverifier_pb.JwtverifierClient]
}

func NewVerifierSDK() *VerifierSDK {
	s := new(VerifierSDK)
	s.client = grpcsdk.New(jwtverifier_pb.NewJwtverifierClient, &jwtverifier_pb.Jwtverifier_ServiceDesc)
	return s
}

func (s *VerifierSDK) Init(opts ...optparams.Option[grpcsdk.SDKConfig]) {
	s.client.Init(opts...)
}

func (s *VerifierSDK) GetLogger() *loggerhelper.Log {
	return s.client.Logger
}

//Close 断开连接
func (c *VerifierSDK) Close() error {
	return c.client.Close()
}

//Meta 查看远端签名器的元信息
func (c *VerifierSDK) Meta() (*jwt_pb.VerifierMeta, error) {
	ctx, cancel := c.client.NewCtx()
	defer cancel()
	Conn, release := c.client.GetClient()
	defer release()
	res, err := Conn.Meta(ctx, &jwtverifier_pb.MetaRequest{})
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

// Verify 校验一个token
func (c *VerifierSDK) Verify(token *jwt_pb.Token, payload interface{}, opts ...optparams.Option[verifyoptions.VerifyOptions]) (*jwt_pb.JwtStatus, error) {
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
	ctx, cancel := c.client.NewCtx()
	defer cancel()
	Conn, release := c.client.GetClient()
	defer release()
	res, err := Conn.Verify(ctx, &query)
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

var DefaultVerifier *VerifierSDK

func init() {
	DefaultVerifier = NewVerifierSDK()
}
