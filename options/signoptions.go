package options

import (
	"time"

	"github.com/scylladb/go-set/strset"
)

type SignOptions struct {
	Sub string
	Aud []string
	Exp int64
	Nbf int64
}

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
func WithAud(aud string) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		s := strset.New(o.Aud...)
		s.Add(aud)
		o.Aud = s.List()
	})
}

//WithExp 设置jwt的有效期截止时间
func WithExp(exp int64) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Exp = exp
	})
}

//WithTimeout 设置jwt从现在起计时多久过期
func WithTimeout(timeout time.Duration) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Exp = time.Now().Add(timeout).Unix()
	})
}

//WithDeadline 设置jwt的有效期截止时间
func WithDeadline(deadline time.Time) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Exp = deadline.Unix()
	})
}

//WithNbf 设置jwt的生效开始时间
func WithNbf(nbf int64) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Nbf = nbf
	})
}

//WithStartAt 设置jwt的生效开始时间
func WithStartAt(nbf time.Time) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Nbf = nbf.Unix()
	})
}

//WithStartDuration 设置jwt开始时间,从调用时间起过多久开始生效
func WithStartDuration(nbftime time.Duration) SignOption {
	return newFuncSignOption(func(o *SignOptions) {
		o.Nbf = time.Now().Add(nbftime).Unix()
	})
}
