package main //import "github.com/Golang-Tools/jwthelper/rsa-generator"
import (
	"os"

	"github.com/Golang-Tools/jwthelper/utils/keygener"
	log "github.com/Golang-Tools/loggerhelper"
	s "github.com/Golang-Tools/schema-entry-go"
)

type CreateKey struct {
	AlgoName string `json:"algoname" jsonschema:"required,description=创建的私钥公钥的算法类型,enum=rsa,enum=ecdsa,enum=ed25519,enum=RSA,enum=ECDSA,enum=ED25519"`
	keyName  string `json:"keyname" jsonschema:"required,description=创建的私钥公钥名"`
}

//Main 服务的入口函数
func (s *CreateKey) Main() {
	algotype, err := keygener.StringTOAlgoType(s.AlgoName)
	if err != nil {
		log.Error("create key get error", log.Dict{"err": err.Error()})
		os.Exit(1)
	}
	err = keygener.GenKey(algotype, s.keyName)
	if err != nil {
		log.Error("create key get error", log.Dict{"err": err.Error()})
		os.Exit(1)
	}
}

func main() {
	root, err := s.New(&s.EntryPointMeta{Name: "jwthelper", Usage: "jwthelper createkey|signer|verifier [options] "})
	if err != nil {
		log.Error("init root node err", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	createkey, err := s.New(&s.EntryPointMeta{Name: "createkey", Usage: "jwthelper serv [options]"}, &CreateKey{
		AlgoName: "rsa",
	})
	if err != nil {
		log.Error("create createkey node get error", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	root.RegistSubNode(createkey)
	root.Parse(os.Args)
}
