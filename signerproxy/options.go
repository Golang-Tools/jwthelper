//选项模块,Init函数的可选参数在这里定义
package proxy

import (
	"github.com/Golang-Tools/optparams"
)

//Option 设置key行为的选项
type Options struct {
	Parallelcallback bool
}

var DefaultOptions = Options{}

//WithParallelCallback 设置初始化后回调并行执行而非串行执行
func WithParallelCallback() optparams.Option[Options] {
	return optparams.NewFuncOption(func(o *Options) {
		o.Parallelcallback = true
	})
}
