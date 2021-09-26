//jwthelper 定义该项目下的各种对象接口
package jwthelper

import (
	declare "github.com/Golang-Tools/jwthelper/jwtrpcdeclare"
	"github.com/Golang-Tools/jwthelper/options"
)

//UniversalJwtHelper 通用jwt的帮助对象
type UniversalJwtHelper interface {
	//Meta 查看签名器元信息
	Meta() *declare.MetaResponse
	// Sign 签名一个token
	Sign(payload []byte, opts ...options.SignOption) (string, error)
	// Verify 用Verifier对象验签
	Verify(tokenstring string) (map[string]interface{}, error)
}

//CanVerify 验证器接口
type CanVerify interface {
}
