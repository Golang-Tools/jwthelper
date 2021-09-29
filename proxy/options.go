//选项模块,Init函数的可选参数在这里定义
package proxy

import "github.com/sirupsen/logrus"

//Option 设置key行为的选项
type Options struct {
	Parallelcallback bool
	Logger           logrus.FieldLogger
}

var DefaultOptions = Options{
	Logger: logrus.New().WithField("logger", "jwthelper"),
}

// Option configures how we set up the connection.
type Option interface {
	Apply(*Options)
}

// func (emptyOption) apply(*Options) {}
type funcOption struct {
	f func(*Options)
}

func (fo *funcOption) Apply(do *Options) {
	fo.f(do)
}

func newFuncOption(f func(*Options)) *funcOption {
	return &funcOption{
		f: f,
	}
}

//WithParallelCallback 设置初始化后回调并行执行而非串行执行
func WithParallelCallback() Option {
	return newFuncOption(func(o *Options) {
		o.Parallelcallback = true
	})
}

//WithLogger 指定使用logger
func WithLogger(logger logrus.FieldLogger) Option {
	return newFuncOption(func(o *Options) {
		o.Logger = logger
	})
}
