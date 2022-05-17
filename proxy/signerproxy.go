package proxy

import (
	jwthelper "github.com/Golang-Tools/jwthelper/v2"
)

//SignerCallback 签名器操作的回调函数
type SignerCallback func(cli jwthelper.UniversalJwtSigner) error

//signerProxy 签名器的代理
type signerProxy struct {
	jwthelper.UniversalJwtSigner
	opts      Options
	callBacks []SignerCallback
}

// NewSignerProxy创建一个新的签名器代理
func NewSignerProxy() *signerProxy {
	proxy := new(signerProxy)
	proxy.opts = DefaultOptions
	return proxy
}

// IsOk 检查代理是否已经可用
func (proxy *signerProxy) IsOk() bool {
	return proxy.UniversalJwtSigner != nil
}

//Init 条件初始化代理对象
func (proxy *signerProxy) Init(signer jwthelper.UniversalJwtSigner, opts ...Option) error {
	if proxy.IsOk() {
		return ErrProxyAllreadySettedUniversalObject
	}
	proxy.UniversalJwtSigner = signer
	for _, opt := range opts {
		opt.Apply(&proxy.opts)
	}
	if proxy.opts.Parallelcallback {
		for _, cb := range proxy.callBacks {
			go func(cb SignerCallback) {
				err := cb(proxy.UniversalJwtSigner)
				if err != nil {
					proxy.opts.Logger.WithError(err).Error("regist callback get error")
				} else {
					proxy.opts.Logger.Debug("regist callback done")
				}
			}(cb)
		}
	} else {
		for _, cb := range proxy.callBacks {
			err := cb(proxy.UniversalJwtSigner)
			if err != nil {
				proxy.opts.Logger.WithError(err).Error("regist callback get error")
			} else {
				proxy.opts.Logger.Debug("regist callback done")
			}
		}
	}
	return nil
}

// Regist 注册回调函数,在init执行后执行回调函数
//如果对象已经设置了被代理客户端则无法再注册回调函数
func (proxy *signerProxy) Regist(cb SignerCallback) error {
	if proxy.IsOk() {
		return ErrProxyAllreadySettedUniversalObject
	}
	proxy.callBacks = append(proxy.callBacks, cb)
	return nil
}
