// jwthelper 定义该项目下的各种对象接口
package jwthelper

import (
	"context"

	"github.com/Golang-Tools/jwthelper/v4/signoptions"
	"github.com/Golang-Tools/jwthelper/v4/verifyoptions"
	"github.com/Golang-Tools/optparams"
)

// UniversalJwtSigner 通用jwt的签名器
type UniversalJwtSigner interface {
	//Meta 查看签名器元信息
	Meta(ctx context.Context) (*SignerMeta, error)
	// Sign 签名一个token
	Sign(ctx context.Context, payload interface{}, opts ...optparams.Option[signoptions.SignOptions]) (*Token, error)
}

// UniversalJwtVerifier 通用jwt的校验器
type UniversalJwtVerifier interface {
	//Meta 查看校验器元信息
	Meta(ctx context.Context) (*VerifierMeta, error)
	// Verify 校验一个签名是否符合
	Verify(ctx context.Context, token *Token, payload interface{}, opts ...optparams.Option[verifyoptions.VerifyOptions]) (*JwtStatus, error)
}
