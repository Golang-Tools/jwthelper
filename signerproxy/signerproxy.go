// 签名器代理模块
package signerproxy

import (
	jwthelper "github.com/Golang-Tools/jwthelper/v4"
	log "github.com/Golang-Tools/loggerhelper/v4"
	"github.com/Golang-Tools/optparams"
)

// moduleName 日志中的模块标识
const moduleName = "jwtsigner-proxy"

// logger 代理使用的日志器,可通过SetLogger替换
var logger = log.Export()

// SetLogger 设置代理使用的日志器(传入nil时保持默认)
func SetLogger(l *log.Log) {
	if l != nil {
		logger = l
	}
}

// Default 默认的签名器代理对象
var Default = NewSignerProxy()

// SignerCallback 签名器操作的回调函数
type SignerCallback func(cli jwthelper.UniversalJwtSigner) error

// SignerProxy 签名器的代理
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

// Init 条件初始化代理对象
func (proxy *SignerProxy) Init(signer jwthelper.UniversalJwtSigner, opts ...optparams.Option[Options]) error {
	if proxy.IsOk() {
		return ErrProxyAllreadySettedUniversalObject
	}
	proxy.UniversalJwtSigner = signer
	proxy.opts = *optparams.GetOption(&proxy.opts, opts...)
	if proxy.opts.Parallelcallback {
		for _, cb := range proxy.callBacks {
			go func(cb SignerCallback) {
				err := cb(proxy.UniversalJwtSigner)
				if err != nil {
					logger.Error("regist callback get error", log.Dict{"module": moduleName, "err": err.Error()})
				} else {
					logger.Debug("regist callback done", log.Dict{"module": moduleName})
				}
			}(cb)
		}
	} else {
		for _, cb := range proxy.callBacks {
			err := cb(proxy.UniversalJwtSigner)
			if err != nil {
				logger.Error("regist callback get error", log.Dict{"module": moduleName, "err": err.Error()})
			} else {
				logger.Debug("regist callback done", log.Dict{"module": moduleName})
			}
		}
	}
	return nil
}

// Regist 注册回调函数,在init执行后执行回调函数
// 如果对象已经设置了被代理客户端则无法再注册回调函数
func (proxy *SignerProxy) Regist(cb SignerCallback) error {
	if proxy.IsOk() {
		return ErrProxyAllreadySettedUniversalObject
	}
	proxy.callBacks = append(proxy.callBacks, cb)
	return nil
}
