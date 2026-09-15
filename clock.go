// 时间源抽象。
package jwthelper

import "time"

// Clock 时间源,用于签名中涉及的时间计算,便于测试注入。
type Clock interface {
	//Now 返回当前时间
	Now() time.Time
}

// systemClock 系统时间源(默认实现)
type systemClock struct{}

// Now 返回当前系统时间
func (systemClock) Now() time.Time { return time.Now() }

// nowUnix 返回当前时间的Unix秒(兼容nil Clock)
func nowUnix(c Clock) int64 {
	if c == nil {
		return time.Now().Unix()
	}
	return c.Now().Unix()
}
