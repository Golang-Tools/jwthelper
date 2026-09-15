package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

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
	if res != nil {
		if res.Payload != nil && string(res.Payload) != "" {
			err := json.Unmarshal(res.Payload, payload)
			if err != nil {
				return nil, err
			}
		}
		jwt_status = pbconv.JwtStatusFromPB(res.JwtStatus)
	}
	if err == nil {
		if res == nil || res.Status == nil {
			return jwt_status, ErrRpcResponseError
		}
		if res.Status.Status == jwtpb.ResponseStatus_FAILED {
			if res.Status.Message != "" {
				return jwt_status, errors.New(res.Status.Message)
			}
			return jwt_status, ErrRpcResponseError
		}
		return jwt_status, nil
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
