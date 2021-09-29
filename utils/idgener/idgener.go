//用于生成jwt的id
package idgener

import (
	"errors"
	"strings"
)

type IDGen interface {
	Next() (string, error)
	String() string
}

func IDGenNameToIDGen(idgen_name string) (IDGen, error) {
	switch strings.ToLower(idgen_name) {
	case "uuid4":
		{
			return &UUID4Gen{}, nil
		}
	case "sonyflake":
		{
			return NewSonyflakeGen(), nil
		}
	default:
		{
			return nil, errors.New("unknown IDGen name")
		}
	}
}
