package main //import "github.com/Golang-Tools/jwthelper/rsa-generator"
import (
	"os"

	"github.com/Golang-Tools/jwthelper/cmd/createkey"
	"github.com/Golang-Tools/jwthelper/cmd/jwtsigner_serv"
	"github.com/Golang-Tools/jwthelper/cmd/jwtverifier_serv"
	log "github.com/Golang-Tools/loggerhelper"
	s "github.com/Golang-Tools/schema-entry-go"
)

func main() {
	root, err := s.New(&s.EntryPointMeta{Name: "jwthelper", Usage: "jwthelper createkey|signer|verifier [options] "})
	if err != nil {
		log.Error("init root node err", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	createkey, err := s.New(&s.EntryPointMeta{Name: "createkey", Usage: "jwthelper createkey [options]"}, &createkey.Node)
	if err != nil {
		log.Error("create createkey node get error", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	signer, err := s.New(&s.EntryPointMeta{Name: "signer", Usage: "jwthelper signer [options]"}, &jwtsigner_serv.Node)
	if err != nil {
		log.Error("create signer node get error", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	verifier, err := s.New(&s.EntryPointMeta{Name: "verifier", Usage: "jwthelper verifier [options]"}, &jwtverifier_serv.Node)
	if err != nil {
		log.Error("create verifier node get error", log.Dict{"err": err.Error()})
		os.Exit(2)
	}

	root.RegistSubNode(createkey)
	root.RegistSubNode(signer)
	root.RegistSubNode(verifier)
	root.Parse(os.Args)
}
