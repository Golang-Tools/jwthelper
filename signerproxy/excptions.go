package proxy

import (
	"errors"
)

//ErrProxyAllreadySettedUniversalObject 代理不能重复设置客户端对象
var ErrProxyAllreadySettedUniversalObject = errors.New("代理不能重复设置对象")

//ErrProxyNotYetSettedUniversalObject 代理还未设置客户端对象
var ErrProxyNotYetSettedUniversalObject = errors.New("代理还未设置对象")
