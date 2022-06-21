package proxy

import (
	jwthelper "github.com/Golang-Tools/jwthelper/v2"
	log "github.com/Golang-Tools/loggerhelper/v2"
	"github.com/Golang-Tools/optparams"
)

var logger *log.Log

var Default *SignerProxy

func init() {
	log.Set(log.WithExtFields(log.Dict{"module": "jwtsigner-proxy"}))
	logger = log.Export()
	log.Set(log.WithExtFields(log.Dict{}))
	Default = NewSignerProxy()
}

//SignerCallback 签名器操作的回调函数
type SignerCallback func(cli jwthelper.UniversalJwtSigner) error

//SignerProxy 签名器的代理
type SignerProxy struct {
	jwthelper.UniversalJwtSigner
	opts      Options
	callBacks []SignerCallback
}

// NewSignerProxy创建一个新的签名器代理
func NewSignerProxy() *SignerProxy {
	proxy := new(SignerProxy)
	proxy.opts = DefaultOptions
	return proxy
}

// IsOk 检查代理是否已经可用
func (proxy *SignerProxy) IsOk() bool {
	return proxy.UniversalJwtSigner != nil
}

//Init 条件初始化代理对象
func (proxy *SignerProxy) Init(signer jwthelper.UniversalJwtSigner, opts ...optparams.Option[Options]) error {
	if proxy.IsOk() {
		return ErrProxyAllreadySettedUniversalObject
	}
	proxy.UniversalJwtSigner = signer
	optparams.GetOption(&proxy.opts, opts...)
	if proxy.opts.Parallelcallback {
		for _, cb := range proxy.callBacks {
			go func(cb SignerCallback) {
				err := cb(proxy.UniversalJwtSigner)
				if err != nil {
					logger.Error("regist callback get error", log.Dict{"err": err.Error()})
				} else {
					logger.Debug("regist callback done")
				}
			}(cb)
		}
	} else {
		for _, cb := range proxy.callBacks {
			err := cb(proxy.UniversalJwtSigner)
			if err != nil {
				logger.Error("regist callback get error", log.Dict{"err": err.Error()})
			} else {
				logger.Debug("regist callback done")
			}
		}
	}
	return nil
}

// Regist 注册回调函数,在init执行后执行回调函数
//如果对象已经设置了被代理客户端则无法再注册回调函数
func (proxy *SignerProxy) Regist(cb SignerCallback) error {
	if proxy.IsOk() {
		return ErrProxyAllreadySettedUniversalObject
	}
	proxy.callBacks = append(proxy.callBacks, cb)
	return nil
}
