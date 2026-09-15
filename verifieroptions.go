package jwthelper

import (
	"github.com/Golang-Tools/jwthelper/v4/utils"
	"github.com/Golang-Tools/optparams"
)

// 签名校验器初始化选项
type VerifierOptions struct {
	Algo            Algo
	DefaultAUD      string
	DefaultISSRange []string
	Key             []byte
	KeyProvider     VerifierKeyProvider //校验密钥提供者,设置后优先于Key
	Clock           Clock               //时间源,默认为系统时间
	Codec           Codec               //payload编解码,默认为标准库encoding/json
	err             error               //选项解析错误(内部使用,构造时返回)
}

// defaultVerifierOptions 默认校验器选项
var defaultVerifierOptions = VerifierOptions{
	Algo:            AlgoHS256,
	Key:             []byte("a secret"),
	DefaultISSRange: []string{},
}

// WithVerifyAlgo 签名校验器的创建参数,设置校验使用的算法
func WithVerifyAlgo(algo Algo) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.Algo = algo
	})
}

// WithDefaultAUD 签名校验器的创建参数,设置解析器默认的aud
func WithDefaultAUD(aud string) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.DefaultAUD = aud
	})
}

// WithDefaultISSRange 签名校验器的创建参数,设置解析器默认的iss范围
func WithDefaultISSRange(iss ...string) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		if o.DefaultISSRange == nil {
			o.DefaultISSRange = []string{}
		}
		o.DefaultISSRange = iss
	})
}

// WithVerifySecretKey 签名校验器的创建参数,对称加密的解密密码
func WithVerifySecretKey(keybytes []byte) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.Key = keybytes
	})
}

// WithVerifySecretKeyFromFile 签名校验器的创建参数,对称加密从指定文件读取内容作为密码;
// 读取失败时错误会保留到NewVerifier的返回值中,不再panic
func WithVerifySecretKeyFromFile(keyPath string) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		keybytes, err := utils.LoadData(keyPath)
		if err != nil {
			o.err = err
			return
		}
		o.Key = keybytes
	})
}

// WithPemPublicKey 签名校验器的创建参数,非对称加密设置以pem格式保存的公钥
func WithPemPublicKey(keybytes []byte) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.Key = keybytes
	})
}

// WithPemPublicKeyFromFile 签名校验器的创建参数,非对称加密设置以pem格式保存的公钥;
// 读取失败时错误会保留到NewVerifier的返回值中,不再panic
func WithPemPublicKeyFromFile(keyPath string) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		keybytes, err := utils.LoadData(keyPath)
		if err != nil {
			o.err = err
			return
		}
		o.Key = keybytes
	})
}

// WithVerifyKeyProvider 签名校验器的创建参数,设置校验密钥提供者(优先于密钥字节设置)
func WithVerifyKeyProvider(provider VerifierKeyProvider) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.KeyProvider = provider
	})
}

// WithVerifyClock 签名校验器的创建参数,设置时间源
func WithVerifyClock(clock Clock) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.Clock = clock
	})
}

// WithVerifyCodec 签名校验器的创建参数,设置payload编解码实现
func WithVerifyCodec(codec Codec) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.Codec = codec
	})
}
