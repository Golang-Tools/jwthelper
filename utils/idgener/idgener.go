//用于生成jwt的id
package idgener

type IDGen interface {
	Next() (string, error)
	String() string
}
