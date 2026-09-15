// jti 生成器抽象。
package jwthelper

// IDGen 用于生成jwt的jti。
// github.com/Golang-Tools/idgener 的生成器天然满足该接口。
type IDGen interface {
	//Next 生成一个id
	Next() (string, error)
	//String 返回生成器名,如 "uuid4"
	String() string
}
