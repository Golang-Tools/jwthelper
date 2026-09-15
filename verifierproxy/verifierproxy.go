// 签名校验器代理模块
package verifierproxy

import (
	jwthelper "github.com/Golang-Tools/jwthelper/v4"
	log "github.com/Golang-Tools/loggerhelper/v4"
	"github.com/Golang-Tools/optparams"
)

// moduleName 日志中的模块标识
const moduleName = "jwtverifier-proxy"

// logger 代理使用的日志器,可通过SetLogger替换
var logger = log.Export()

// SetLogger 设置代理使用的日志器(传入nil时保持默认)
func SetLogger(l *log.Log) {
	if l != nil {
		logger = l
	}
}

// Default 默认的签名校验器代理对象
var Default = NewVerifierProxy()

// VerifierCallback 签名校验器操作的回调函数
type VerifierCallback func(cli jwthelper.UniversalJwtVerifier) error

// VerifierProxy 签名校验器的代理
type VerifierProxy struct {
	jwthelper.UniversalJwtVerifier
	opts      Options
	callBacks []VerifierCallback
}

// NewVerifierProxy创建一个新的签名校验器代理
func NewVerifierProxy() *VerifierProxy {
	proxy := new(VerifierProxy)
	proxy.opts = DefaultOptions
	return proxy
}

// IsOk 检查代理是否已经可用
func (proxy *VerifierProxy) IsOk() bool {
	return proxy.UniversalJwtVerifier != nil
}

// Init 条件初始化代理对象
func (proxy *VerifierProxy) Init(verifier jwthelper.UniversalJwtVerifier, opts ...optparams.Option[Options]) error {
	if proxy.IsOk() {
		return ErrProxyAllreadySettedUniversalObject
	}
	proxy.UniversalJwtVerifier = verifier
	proxy.opts = *optparams.GetOption(&proxy.opts, opts...)
	if proxy.opts.Parallelcallback {
		for _, cb := range proxy.callBacks {
			go func(cb VerifierCallback) {
				err := cb(proxy.UniversalJwtVerifier)
				if err != nil {
					logger.Error("regist callback get error", log.Dict{"module": moduleName, "err": err.Error()})
				} else {
					logger.Debug("regist callback done", log.Dict{"module": moduleName})
				}
			}(cb)
		}
	} else {
		for _, cb := range proxy.callBacks {
			err := cb(proxy.UniversalJwtVerifier)
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
func (proxy *VerifierProxy) Regist(cb VerifierCallback) error {
	if proxy.IsOk() {
		return ErrProxyAllreadySettedUniversalObject
	}
	proxy.callBacks = append(proxy.callBacks, cb)
	return nil
}
