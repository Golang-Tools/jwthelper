// signoptions 签名器签名方法的参数
package signoptions

import (
	"time"

	"github.com/scylladb/go-set/strset"
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

type SignOption interface {
	Apply(*SignOptions)
}

// func (emptyOption) apply(*SignOptions) {}
type funcSignOption struct {
	f func(*SignOptions)
}

func (fo *funcSignOption) Apply(do *SignOptions) {
	fo.f(do)
}

func newFuncSignOption(f func(*SignOptions)) *funcSignOption {
	return &funcSignOption{
		f: f,
	}
}

//WithSub 设置jwt所面向的用户,即它的所有人
func WithSub(sub string) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Sub = sub
	})
}

//WithAud 设置接收jwt的一方标识,即访问权限的所有方,比如`b.com`
func WithAud(aud ...string) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		if o.Aud == nil {
			o.Aud = []string{}
		}
		s := strset.New(o.Aud...)
		s.Add(aud...)
		o.Aud = s.List()
	})
}

//AddAud 设置接收jwt的一方标识,即访问权限的所有方,比如`b.com`
func AddAud(aud string) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		if o.Aud == nil {
			o.Aud = []string{}
		}
		s := strset.New(o.Aud...)
		s.Add(aud)
		o.Aud = s.List()
	})
}

//WithExpAt 设置jwt的有效期截止时间
func WithExpAt(exp time.Time) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Exp = exp.Unix()
	})
}

//WithTTL 设置jwt的生命周期
func WithTTL(ttl time.Duration) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Exp = time.Now().Add(ttl).Unix()
	})
}

//WithNbf 设置jwt的生效开始时间
func WithNbf(nbf int64) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Nbf = nbf
	})
}

//WillEffectiveOn 设置jwt的生效开始时间
func WillEffectiveOn(nbf time.Time) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Nbf = nbf.Unix()
	})
}

//WillEffectiveAfter 设置jwt开始时间,从调用时间起过多久开始生效
func WillEffectiveAfter(nbftime time.Duration) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Nbf = time.Now().Add(nbftime).Unix()
	})
}

//WithRefreshExpAt 设置jwt的伴生refreshtoken有效期截止时间
func WithRefreshExpAt(exp time.Time) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.RefreshExp = exp.Unix()
	})
}

//WithRefreshTTL 设置jwt的伴生refreshtoken的生命周期
func WithRefreshTTL(ttl time.Duration) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.RefreshExp = time.Now().Add(ttl).Unix()
	})
}

//WithJTI 设置jwt的jti,不设置则会使用默认生成器创建
func WithJTI(jti string) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Jti = jti
	})
}
