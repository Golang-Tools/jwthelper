// payload 编解码抽象。
package jwthelper

import "encoding/json"

// Codec 定义payload与claims的JSON编解码方式,默认使用标准库encoding/json。
type Codec interface {
	//Marshal 将对象编码为JSON字节
	Marshal(v any) ([]byte, error)
	//Unmarshal 将JSON字节解码到对象
	Unmarshal(data []byte, v any) error
}

// stdJSONCodec 标准库encoding/json实现(默认)
type stdJSONCodec struct{}

// Marshal 标准库json编码
func (stdJSONCodec) Marshal(v any) ([]byte, error) { return json.Marshal(v) }

// Unmarshal 标准库json解码
func (stdJSONCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// codecOrStd 返回可用的Codec(兼容nil)
func codecOrStd(c Codec) Codec {
	if c == nil {
		return stdJSONCodec{}
	}
	return c
}
