// signoptions 签名器签名方法的参数
package signoptions

import (
	"time"

	"github.com/Golang-Tools/optparams"
	mapset "github.com/deckarep/golang-set/v2"
)

//SignOptions 签名函数参数
type SignOptions struct {
	Sub        string
	Aud        []string
	Exp        int64 // 过期时间戳
	Nbf        int64
	Jti        string
	RefreshExp int64 // >0时会设置refresh_token,其过期时间就是这个字段控制,这个字段也是时间戳
}

var DefaultSignOptions = SignOptions{}

//WithSub 设置jwt所面向的用户,即它的所有人
func WithSub(sub string) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		o.Sub = sub
	})
}

//WithAud 设置接收jwt的一方标识,即访问权限的所有方,比如`b.com`
func WithAud(aud ...string) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		if o.Aud == nil {
			o.Aud = []string{}
		}
		s := mapset.NewSet(o.Aud...)
		for _, a := range aud {
			s.Add(a)
		}

		o.Aud = s.ToSlice()
	})
}

//AddAud 设置接收jwt的一方标识,即访问权限的所有方,比如`b.com`
func AddAud(aud string) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		if o.Aud == nil {
			o.Aud = []string{}
		}
		s := mapset.NewSet(o.Aud...)
		s.Add(aud)
		o.Aud = s.ToSlice()
	})
}

//WithExpAt 设置jwt的有效期截止时间
func WithExpAt(exp time.Time) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		o.Exp = exp.Unix()
	})
}

//WithTTL 设置jwt的生命周期
func WithTTL(ttl time.Duration) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		o.Exp = time.Now().Add(ttl).Unix()
	})
}

//WithNbf 设置jwt的生效开始时间
func WithNbf(nbf int64) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		o.Nbf = nbf
	})
}

//WillEffectiveOn 设置jwt的生效开始时间
func WillEffectiveOn(nbf time.Time) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		o.Nbf = nbf.Unix()
	})
}

//WillEffectiveAfter 设置jwt开始时间,从调用时间起过多久开始生效
func WillEffectiveAfter(nbftime time.Duration) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		o.Nbf = time.Now().Add(nbftime).Unix()
	})
}

//WithRefreshExpAt 设置jwt的伴生refreshtoken有效期截止时间
func WithRefreshExpAt(exp time.Time) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		o.RefreshExp = exp.Unix()
	})
}

//WithRefreshTTL 设置jwt的伴生refreshtoken的生命周期
func WithRefreshTTL(ttl time.Duration) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		o.RefreshExp = time.Now().Add(ttl).Unix()
	})
}

//WithJTI 设置jwt的jti,不设置则会使用默认生成器创建
func WithJTI(jti string) optparams.Option[SignOptions] {
	return optparams.NewFuncOption(func(o *SignOptions) {
		o.Jti = jti
	})
}
