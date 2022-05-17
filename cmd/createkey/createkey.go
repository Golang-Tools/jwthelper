package createkey

import (
	"os"

	"github.com/Golang-Tools/jwthelper/utils/keygener"
	log "github.com/Golang-Tools/loggerhelper/v2"
)

type CreateKey struct {
	AlgoName string `json:"algo_name" jsonschema:"required,description=创建的私钥公钥的算法类型,enum=rsa,enum=ecdsa,enum=ed25519,enum=RSA,enum=ECDSA,enum=ED25519,default=rsa"`
	KeyName  string `json:"key_name" jsonschema:"required,description=创建的私钥公钥名"`
}

//Main 服务的入口函数
func (s *CreateKey) Main() {
	algotype, err := keygener.StringTOAlgoType(s.AlgoName)
	if err != nil {
		log.Error("create key get error", log.Dict{"err": err.Error()})
		os.Exit(1)
	}
	err = keygener.GenKey(algotype, s.KeyName)
	if err != nil {
		log.Error("create key get error", log.Dict{"err": err.Error()})
		os.Exit(1)
	}
}
