package idgener

import (
	"strconv"
	"time"

	"github.com/Golang-Tools/jwthelper/utils/machineid"
	"github.com/sony/sonyflake"
)

type SonyflakeGen struct {
	generator *sonyflake.Sonyflake
	opt       sonyflake.Settings
}

var defaultSetting = sonyflake.Settings{
	StartTime: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
}

func NewSonyflakeGen() *SonyflakeGen {
	g := new(SonyflakeGen)
	g.opt = sonyflake.Settings{
		StartTime: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		MachineID: func() (uint16, error) {
			return machineid.MachineID, nil
		},
	}
	g.generator = sonyflake.NewSonyflake(g.opt)
	return g
}

//Next 随机生成key
func (g *SonyflakeGen) Next() (string, error) {
	id, err := g.generator.NextID()
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(id, 32), nil
}

func (g *SonyflakeGen) String() string {
	return "sonyflake"
}
