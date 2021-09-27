package idgener

import (
	uuid "github.com/satori/go.uuid"
)

type UUID4Gen struct{}

func (g *UUID4Gen) Next() (string, error) {
	return uuid.NewV4().String(), nil
}
func (g *UUID4Gen) String() string {
	return "uuid4"
}
