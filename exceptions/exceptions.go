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

// ErrVerifyToken 校验token错误
var ErrVerifyToken = errors.New("verify Token error")

// //ErrLoadKey 密码无法加载
// var ErrLoadKey = errors.New("couldn't read key")

// var TokenInvalidError error = errors.New("Token is invalid")
// var VerifyTokenError error = errors.New("Verify Token error")

// // ErrConfigParams 配置参数错误
// var ErrConfigParams = errors.New("config params error")

// // ErrExpOutOfRange 过期时间超出范围
// var ErrExpOutOfRange = errors.New("exp is out of range")

// // //ErrProxyNotInited 数据库代理未初始化错误
// // var ErrProxyNotInited = errors.New("proxy not inited yet")

// // //ErrProxyAlreadyInited 代理已经被初始化过了
// // var ErrProxyAlreadyInited = errors.New("proxy already inited yet")

// // ErrUnexpectedAlgo 算法类型错误
// var ErrUnexpectedAlgo = errors.New("unknown algo type key")

// // ErrParseClaimsToJSON 无法加载JSON
// var ErrParseClaimsToJSON = errors.New("couldn't parse claims JSON")

// // ErrSignToken 签名错误
// var ErrSignToken = errors.New("Error signing token")
