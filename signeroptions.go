package jwthelper

import (
	"fmt"
	"strings"
	"time"

	"github.com/Golang-Tools/jwthelper/jwt_pb"
	"github.com/Golang-Tools/jwthelper/utils"
	"github.com/Golang-Tools/jwthelper/utils/idgener"
	"github.com/Golang-Tools/jwthelper/utils/machineid"
)

// 签名器初始化选项
type SignerOptions struct {
	Algo                     jwt_pb.EncryptionAlgorithm
	Key                      []byte
	Iss                      string
	DefaultTTL               time.Duration //默认token超时
	DefaultEffectiveInterval time.Duration //默认token生效离签发时间间隔
	JtiGen                   idgener.IDGen //jti的生成器
}

var DefaultSignerOptions = SignerOptions{
	Algo:       jwt_pb.EncryptionAlgorithm_HS256,
	Iss:        fmt.Sprintf("%s-%s", machineid.GetMachineID(), jwt_pb.EncryptionAlgorithm_HS256.String()),
	DefaultTTL: time.Minute * 10,
	JtiGen:     &idgener.UUID4Gen{},
	Key:        []byte("a secret"),
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

//WithSignIss 签名器的创建参数,设置jwt签发者标识
func WithSignIss(iss string) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.Iss = iss
	})
}

//WithDefaultTTL 签名器的创建参数,设置jwt签发者的默认令牌存在时长,注意过期时间为开始生效时间+令牌存在时长
func WithDefaultTTL(defaultTTL time.Duration) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.DefaultTTL = defaultTTL
	})
}

//WithDefaultEffectiveInterval 签名器的创建参数,设置jwt签发者所谓默认令牌开始生效间隔
func WithDefaultEffectiveInterval(defaultEffectiveInterval time.Duration) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.DefaultEffectiveInterval = defaultEffectiveInterval
	})
}

//WithSignJtiGen 签名器的创建参数,设置jwt签发id生成器
func WithSignJtiGen(jtiGen idgener.IDGen) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.JtiGen = jtiGen
	})
}

//WithSignAlgo 签名器的创建参数,设置jwt签发id生成器,如果Iss以机器ID开头则会任务Iss是默认格式,会更新默认Iss的后半段为算法名
func WithSignAlgo(algo jwt_pb.EncryptionAlgorithm) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.Algo = algo
		if strings.HasPrefix(o.Iss, machineid.GetMachineID()) {
			o.Iss = fmt.Sprintf("%s-%s", machineid.GetMachineID(), algo.String())
		}
	})
}

//WithSignSecretKey 签名器的创建参数,对称加密设置密码
func WithSignSecretKey(keybytes []byte) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.Key = keybytes
	})
}

//WithSignSecretKeyFromFile 签名器的创建参数,对称加密从指定文件读取内容作为密码
func WithSignSecretKeyFromFile(keyPath string) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		keybytes, err := utils.LoadData(keyPath)
		if err != nil {
			panic(err)
		}
		o.Key = keybytes
	})
}

//WithPemPrivateKey 签名器的创建参数,非对称加密设置以pem格式保存的私钥
func WithPemPrivateKey(keybytes []byte) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		o.Key = keybytes
	})
}

//WithPemPrivateKeyFromFile 签名器的创建参数,非对称加密设置以pem格式保存的私钥
func WithPemPrivateKeyFromFile(keyPath string) SignerOption {
	return newFuncSignerOption(func(o *SignerOptions) {
		keybytes, err := utils.LoadData(keyPath)
		if err != nil {
			panic(err)
		}
		o.Key = keybytes
	})
}
