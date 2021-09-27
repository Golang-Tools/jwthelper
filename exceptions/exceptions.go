//exceptions 定义异常
package exceptions

import (
	"errors"
)

//ErrAlgoType 算法类型不支持
var ErrAlgoType = errors.New("unknown algo type key")

//ErrUnsupportAlgoType 算法类型在当前场景下不被支持
var ErrUnsupportAlgoType = errors.New("algo type not support in this satuation")

//ErrAlgoTypeNotMatch 算法类型和验证器不匹配
var ErrAlgoTypeNotMatch = errors.New("algo type not match")

//ErrLoadPrivateKey 私钥无法阅读
var ErrLoadPrivateKey = errors.New("couldn't read private key")

// ErrLoadPublicKey 公钥无法阅读
var ErrLoadPublicKey = errors.New("couldn't read public key")

var (
	//ErrAccessTokenNotFound 未找到access_token
	ErrAccessTokenNotFound = errors.New("access token not found")
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
	// ErrRefreshTokenIssNotInRange refresh_token的iss不在参数范围内
	ErrRefreshTokenIssNotInRange = errors.New("refresh token iss not in range")
	// ErrRefreshTokenNotHaveEXP refresh_token没有设置exp
	ErrRefreshTokenNotHaveEXP = errors.New("refresh token not have exp")

	// ErrRefreshTokenValidationError refresh_token的校验错误
	ErrRefreshTokenValidationError = errors.New("refresh token not validate")
	// ErrRefreshTokenParseError refresh_token的解析错误
	ErrRefreshTokenParseError = errors.New("refresh token can not parse")
)


