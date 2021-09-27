//jwthelper 定义该项目下的各种对象接口
package jwthelper

import (
	"time"

	"github.com/Golang-Tools/jwthelper/jwt_pb"
	"github.com/Golang-Tools/jwthelper/signoptions"
)

//UniversalJwtSigner 通用jwt的签名器
type UniversalJwtSigner interface {
	//Meta 查看签名器元信息
	Meta() *jwt_pb.SignerMeta
	// Sign 签名一个token
	Sign(payload interface{}, opts ...signoptions.SignOption) (*jwt_pb.Token, error)
}

//UniversalJwtVerifier 通用jwt的签名器
type UniversalJwtVerifier interface {
	//Meta 查看签名器元信息
	Meta() *jwt_pb.VerifierMeta
	// 校验一个签名是否复合
	Verify(token *jwt_pb.Token, payload interface{}, opts ...signoptions.SignOption) (time.Duration, error)
}
