package proxy

import (
	jwthelper "github.com/Golang-Tools/jwthelper/v2"
	log "github.com/Golang-Tools/loggerhelper/v2"
	"github.com/Golang-Tools/optparams"
)

var logger *log.Log

var Default *verifierProxy

func init() {
	log.Set(log.WithExtFields(log.Dict{"module": "jwtverifier-proxy"}))
	logger = log.Export()
	log.Set(log.WithExtFields(log.Dict{}))
	Default = NewVerifierProxy()
}

//VerifierCallback 签名校验器操作的回调函数
type VerifierCallback func(cli jwthelper.UniversalJwtVerifier) error

//verifierProxy 签名校验器的代理
type verifierProxy struct {
	jwthelper.UniversalJwtVerifier
	opts      Options
	callBacks []VerifierCallback
}

// NewVerifierProxy创建一个新的签名校验器代理
func NewVerifierProxy() *verifierProxy {
	proxy := new(verifierProxy)
	proxy.opts = DefaultOptions
	return proxy
}

// IsOk 检查代理是否已经可用
func (proxy *verifierProxy) IsOk() bool {
	return proxy.UniversalJwtVerifier != nil
}

//Init 条件初始化代理对象
func (proxy *verifierProxy) Init(Verifier jwthelper.UniversalJwtVerifier, opts ...optparams.Option[Options]) error {
	if proxy.IsOk() {
		return ErrProxyAllreadySettedUniversalObject
	}
	proxy.UniversalJwtVerifier = Verifier
	optparams.GetOption(&proxy.opts, opts...)
	if proxy.opts.Parallelcallback {
		for _, cb := range proxy.callBacks {
			go func(cb VerifierCallback) {
				err := cb(proxy.UniversalJwtVerifier)
				if err != nil {
					logger.Error("regist callback get error", log.Dict{"err": err.Error()})
				} else {
					logger.Debug("regist callback done")
				}
			}(cb)
		}
	} else {
		for _, cb := range proxy.callBacks {
			err := cb(proxy.UniversalJwtVerifier)
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
func (proxy *verifierProxy) Regist(cb VerifierCallback) error {
	if proxy.IsOk() {
		return ErrProxyAllreadySettedUniversalObject
	}
	proxy.callBacks = append(proxy.callBacks, cb)
	return nil
}
