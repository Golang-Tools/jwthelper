package jwthelper

import (
	"fmt"
	"strings"
	"time"

	"github.com/Golang-Tools/idgener"
	"github.com/Golang-Tools/idgener/machineid"
	"github.com/Golang-Tools/jwthelper/v4/utils"
	"github.com/Golang-Tools/optparams"
)

// 签名器初始化选项
type SignerOptions struct {
	Algo                     Algo
	Key                      []byte
	Iss                      string
	DefaultTTL               time.Duration     //默认token超时
	DefaultEffectiveInterval time.Duration     //默认token生效离签发时间间隔
	JtiGen                   IDGen             //jti的生成器
	KeyProvider              SignerKeyProvider //签名密钥提供者,设置后优先于Key
	Clock                    Clock             //时间源,默认为系统时间
	Codec                    Codec             //payload编解码,默认为标准库encoding/json
	err                      error             //选项解析错误(内部使用,构造时返回)
}

// defaultSignerOptions 默认签名器选项
var defaultSignerOptions = SignerOptions{
	Algo:       AlgoHS256,
	Iss:        fmt.Sprintf("%s-%s", machineid.MachineIDStr, AlgoHS256),
	DefaultTTL: time.Minute * 10,
	JtiGen:     idgener.DefaultUUID4,
	Key:        []byte("a secret"),
}

// WithSignIss 签名器的创建参数,设置jwt签发者标识
func WithSignIss(iss string) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		o.Iss = iss
	})
}

// WithDefaultTTL 签名器的创建参数,设置jwt签发者的默认令牌存在时长,注意过期时间为开始生效时间+令牌存在时长
func WithDefaultTTL(defaultTTL time.Duration) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		o.DefaultTTL = defaultTTL
	})
}

// WithDefaultEffectiveInterval 签名器的创建参数,设置jwt签发者所谓默认令牌开始生效间隔
func WithDefaultEffectiveInterval(defaultEffectiveInterval time.Duration) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		o.DefaultEffectiveInterval = defaultEffectiveInterval
	})
}

// WithSignJtiGen 签名器的创建参数,设置jwt签发id生成器
func WithSignJtiGen(jtiGen IDGen) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		o.JtiGen = jtiGen
	})
}

// WithSignAlgo 签名器的创建参数,设置签名算法;如果Iss以机器ID开头则认为Iss是默认格式,会更新默认Iss的后半段为算法名
func WithSignAlgo(algo Algo) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		o.Algo = algo
		if strings.HasPrefix(o.Iss, machineid.MachineIDStr) {
			o.Iss = fmt.Sprintf("%s-%s", machineid.MachineIDStr, algo)
		}
	})
}

// WithSignSecretKey 签名器的创建参数,对称加密设置密码
func WithSignSecretKey(keybytes []byte) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		o.Key = keybytes
	})
}

// WithSignSecretKeyFromFile 签名器的创建参数,对称加密从指定文件读取内容作为密码;
// 读取失败时错误会保留到NewSigner的返回值中,不再panic
func WithSignSecretKeyFromFile(keyPath string) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		keybytes, err := utils.LoadData(keyPath)
		if err != nil {
			o.err = err
			return
		}
		o.Key = keybytes
	})
}

// WithPemPrivateKey 签名器的创建参数,非对称加密设置以pem格式保存的私钥
func WithPemPrivateKey(keybytes []byte) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		o.Key = keybytes
	})
}

// WithPemPrivateKeyFromFile 签名器的创建参数,非对称加密设置以pem格式保存的私钥;
// 读取失败时错误会保留到NewSigner的返回值中,不再panic
func WithPemPrivateKeyFromFile(keyPath string) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		keybytes, err := utils.LoadData(keyPath)
		if err != nil {
			o.err = err
			return
		}
		o.Key = keybytes
	})
}

// WithSignKeyProvider 签名器的创建参数,设置签名密钥提供者(优先于密钥字节设置)
func WithSignKeyProvider(provider SignerKeyProvider) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		o.KeyProvider = provider
	})
}

// WithSignClock 签名器的创建参数,设置时间源
func WithSignClock(clock Clock) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		o.Clock = clock
	})
}

// WithSignCodec 签名器的创建参数,设置payload编解码实现
func WithSignCodec(codec Codec) optparams.Option[SignerOptions] {
	return optparams.NewFuncOption(func(o *SignerOptions) {
		o.Codec = codec
	})
}
