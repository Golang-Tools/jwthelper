package jwthelper

import (
	"github.com/Golang-Tools/jwthelper/v2/jwt_pb"
	"github.com/Golang-Tools/jwthelper/v2/utils"
	"github.com/Golang-Tools/optparams"
)

// 签名校验器初始化选项
type VerifierOptions struct {
	Algo            jwt_pb.EncryptionAlgorithm
	DefaultAUD      string
	DefaultISSRange []string
	Key             []byte
}

var DefaultVerifierOptions = VerifierOptions{
	Algo:            jwt_pb.EncryptionAlgorithm_HS256,
	Key:             []byte("a secret"),
	DefaultISSRange: []string{},
}

//WithVerifyAlgo 签名校验器的创建参数,设置jwt签发id生成器,如果Iss以机器ID开头则会任务Iss是默认格式,会更新默认Iss的后半段为算法名
func WithVerifyAlgo(algo jwt_pb.EncryptionAlgorithm) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.Algo = algo
	})
}

//WithDefaultAUD 签名校验器的创建参数,设置解析器默认的aud
func WithDefaultAUD(aud string) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.DefaultAUD = aud
	})
}

//WithDefaultISSRange 签名校验器的创建参数,设置解析器默认的iss范围
func WithDefaultISSRange(iss ...string) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		if o.DefaultISSRange == nil {
			o.DefaultISSRange = []string{}
		}
		o.DefaultISSRange = iss
	})
}

//WithVerifySecretKey 签名校验器的创建参数,对称加密的解密密码
func WithVerifySecretKey(keybytes []byte) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.Key = keybytes
	})
}

//WithVerifySecretKeyFromFile 签名校验器的创建参数,对称加密从指定文件读取内容作为密码
func WithVerifySecretKeyFromFile(keyPath string) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		keybytes, err := utils.LoadData(keyPath)
		if err != nil {
			panic(err)
		}
		o.Key = keybytes
	})
}

//WithPemPublicKey 签名校验器的创建参数,非对称加密设置以pem格式保存的公钥
func WithPemPublicKey(keybytes []byte) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		o.Key = keybytes
	})
}

//WithPemPublicKeyFromFile 签名校验器的创建参数,非对称加密设置以pem格式保存的公钥
func WithPemPublicKeyFromFile(keyPath string) optparams.Option[VerifierOptions] {
	return optparams.NewFuncOption(func(o *VerifierOptions) {
		keybytes, err := utils.LoadData(keyPath)
		if err != nil {
			panic(err)
		}
		o.Key = keybytes
	})
}
