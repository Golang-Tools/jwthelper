// exceptions 定义异常
package exceptions

import (
	"errors"
)

// ErrAlgoType 算法类型不支持
var ErrAlgoType = errors.New("unknown algo type key")

// ErrUnsupportAlgoType 算法类型在当前场景下不被支持
var ErrUnsupportAlgoType = errors.New("algo type not support in this satuation")

// ErrAlgoTypeNotMatch 算法类型和验证器不匹配
var ErrAlgoTypeNotMatch = errors.New("algo type not match")

// ErrLoadPrivateKey 私钥无法阅读
var ErrLoadPrivateKey = errors.New("couldn't read private key")

// ErrLoadPublicKey 公钥无法阅读
var ErrLoadPublicKey = errors.New("couldn't read public key")

var (
	//ErrAccessTokenNotFound 未找到access_token
	ErrAccessTokenNotFound = errors.New("access token not found")
)

var (
	//ErrSignWithRefreshTokenNeedSUB 签名带refresh token的jwt必须带有参数sub
	ErrSignWithRefreshTokenNeedSUB = errors.New("sign with refresh token need SUB")
)

/** 校验错误
 */
var (
	// ErrValidationErrorUnknown 校验token时产生的未知错误错误
	ErrValidationErrorUnknown = errors.New("unknown verify Token error")
	// ErrValidationErrorMalformed 令牌格式错误
	ErrValidationErrorMalformed = errors.New("token is malformed")
	//ErrValidationErrorUnverifiable 由于签名问题无法验证令牌
	ErrValidationErrorUnverifiable = errors.New("token could not be verified because of signing problems")
	//ErrValidationErrorSignatureInvalid 签名验证失败
	ErrValidationErrorSignatureInvalid = errors.New("signature validation failed")

	// Standard Claim validation errors
	//ErrValidationErrorAudience AUD校验错误
	ErrValidationErrorAudience = errors.New("AUD validation failed")
	//ErrValidationErrorSubject SUB校验错误
	ErrValidationErrorSubject = errors.New("SUB validation failed")
	//ErrValidationErrorExpired 令牌超时
	ErrValidationErrorExpired = errors.New("EXP validation failed")
	//ErrValidationErrorIssuedAt 令牌签发时间错误
	ErrValidationErrorIssuedAt = errors.New("IAT validation failed")
	//ErrValidationErrorIssuer 令牌签发人错误
	ErrValidationErrorIssuer = errors.New("ISS validation failed")
	//ErrValidationErrorNotValidYet 令牌未到可用时间
	ErrValidationErrorNotValidYet = errors.New("NBF validation failed")
	//ErrValidationErrorId JTI验证失败
	ErrValidationErrorId = errors.New("JTI validation failed")
	//ErrValidationErrorClaimsInvalid 通用的声明校验错误
	ErrValidationErrorClaimsInvalid = errors.New("generic claims validation error")
	//ErrValidationErrorCanNotHandle 未能处理的错误
	ErrValidationErrorCanNotHandle = errors.New("claims validation error can not handle")
)

/** refresh_token校验错误
* refresh_token作为access_token的伴生物应该和access_token的sub以及aud完全一致;iss可以不一致,但如果有指定iss范围应该都在同一个范围内
 */
var (
	// ErrRefreshTokenSUBNotMatch refresh_token的sub和access_token的sub不一致
	ErrRefreshTokenSUBNotMatch = errors.New("refresh token sub not match")
	// ErrRefreshTokenAudNotMatch refresh_token的sub和access_token的aud范围不一致
	ErrRefreshTokenAudNotMatch = errors.New("refresh token aud not match")
	//ErrRefreshTokenJtiNotMatch refresh_token的jti和access_token的不一致
	ErrRefreshTokenJtiNotMatch = errors.New("refresh token jti not match")
	// ErrRefreshTokenIssNotInRange refresh_token的iss不在参数范围内
	ErrRefreshTokenIssNotInRange = errors.New("refresh token iss not in range")
	// ErrRefreshTokenNotHaveEXP refresh_token没有设置exp
	ErrRefreshTokenNotHaveEXP = errors.New("refresh token not have exp")

	// ErrRefreshTokenValidationError refresh_token的校验错误
	ErrRefreshTokenValidationError = errors.New("refresh token not validate")
	// ErrRefreshTokenParseError refresh_token的解析错误
	ErrRefreshTokenParseError = errors.New("refresh token can not parse")
)

/** 结构化校验错误
 */

// ValidationError 字段级校验错误,包装具体的哨兵错误,支持 errors.Is/As。
type ValidationError struct {
	//Field 校验失败的字段名(sub/aud/iss/exp/jti 等)
	Field string
	//Err 具体错误(可用 errors.Is 判断)
	Err error
}

// Error 实现error接口
func (e *ValidationError) Error() string {
	if e == nil {
		return ""
	}
	if e.Field == "" {
		return e.Err.Error()
	}
	return e.Field + " : " + e.Err.Error()
}

// Unwrap 支持errors.Is/As
func (e *ValidationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// KindOf 返回错误的稳定分类名(供传输层映射错误码),nil 返回空串,未识别返回 "unknown"
func KindOf(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrValidationErrorExpired):
		return "validation_expired"
	case errors.Is(err, ErrValidationErrorMalformed):
		return "validation_malformed"
	case errors.Is(err, ErrValidationErrorUnverifiable):
		return "validation_unverifiable"
	case errors.Is(err, ErrValidationErrorSignatureInvalid):
		return "validation_signature_invalid"
	case errors.Is(err, ErrValidationErrorAudience):
		return "validation_audience"
	case errors.Is(err, ErrValidationErrorSubject):
		return "validation_subject"
	case errors.Is(err, ErrValidationErrorIssuedAt):
		return "validation_issued_at"
	case errors.Is(err, ErrValidationErrorIssuer):
		return "validation_issuer"
	case errors.Is(err, ErrValidationErrorNotValidYet):
		return "validation_not_valid_yet"
	case errors.Is(err, ErrValidationErrorId):
		return "validation_id"
	case errors.Is(err, ErrValidationErrorClaimsInvalid):
		return "validation_claims_invalid"
	case errors.Is(err, ErrValidationErrorCanNotHandle):
		return "validation_can_not_handle"
	case errors.Is(err, ErrValidationErrorUnknown):
		return "validation_unknown"
	case errors.Is(err, ErrAccessTokenNotFound):
		return "access_token_not_found"
	case errors.Is(err, ErrSignWithRefreshTokenNeedSUB):
		return "sign_with_refresh_token_need_sub"
	case errors.Is(err, ErrRefreshTokenNotHaveEXP):
		return "refresh_token_not_have_exp"
	case errors.Is(err, ErrRefreshTokenSUBNotMatch):
		return "refresh_token_sub_not_match"
	case errors.Is(err, ErrRefreshTokenAudNotMatch):
		return "refresh_token_aud_not_match"
	case errors.Is(err, ErrRefreshTokenJtiNotMatch):
		return "refresh_token_jti_not_match"
	case errors.Is(err, ErrRefreshTokenIssNotInRange):
		return "refresh_token_iss_not_in_range"
	case errors.Is(err, ErrRefreshTokenValidationError):
		return "refresh_token_not_validate"
	case errors.Is(err, ErrRefreshTokenParseError):
		return "refresh_token_parse_error"
	case errors.Is(err, ErrAlgoType):
		return "algo_type_unknown"
	case errors.Is(err, ErrUnsupportAlgoType):
		return "algo_type_unsupport"
	case errors.Is(err, ErrAlgoTypeNotMatch):
		return "algo_type_not_match"
	default:
		return "unknown"
	}
}
