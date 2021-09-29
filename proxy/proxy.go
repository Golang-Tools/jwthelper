//proxy 签名器和签名校验器的代理模块
package proxy

//Signer 默认的签名器代理对象
var Signer = NewSignerProxy()

//Verifier 默认的签名校验器代理对象
var Verifier = NewVerifierProxy()
