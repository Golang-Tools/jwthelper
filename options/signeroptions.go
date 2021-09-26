package options

import (
	"time"

	"github.com/Golang-Tools/jwthelper/idgener"
)

type IDGen interface {
	Next() (string, error)
	String() string
}

type SignerOptions struct {
	Iss                      string
	DefaultTTL               time.Duration
	DefaultEffectiveInterval time.Duration
	JtiGen                   IDGen
}

var DefaultSignerOptions = SignerOptions{
	JtiGen: &idgener.UUID4Gen{},
}

type SignerOption interface {
	Apply(*SignerOptions)
}

// func (emptyOption) apply(*SignOptions) {}
type funcSignerOption struct {
	f func(*SignerOptions)
}

func (fo *funcSignerOption) Apply(do *SignerOptions) {
	fo.f(do)
}

func newFuncSignerOption(f func(*SignerOptions)) *funcSignerOption {
	return &funcSignerOption{
		f: f,
	}
}

//WithIss 设置jwt签发者标识
func WithIss(iss string) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.Iss = iss
	})
}

//WithDefaultTTL 设置jwt签发者的默认令牌存在时长,注意过期时间为开始生效时间+令牌存在时长
func WithDefaultTTL(defaultTTL time.Duration) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.DefaultTTL = defaultTTL
	})
}

//WithDefaultEffectiveInterval 设置jwt签发者所谓默认令牌开始生效间隔
func WithDefaultEffectiveInterval(defaultEffectiveInterval time.Duration) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.DefaultEffectiveInterval = defaultEffectiveInterval
	})
}

//WithJtiGen 设置jwt签发id生成器
func WithJtiGen(jtiGen IDGen) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.JtiGen = jtiGen
	})
}
