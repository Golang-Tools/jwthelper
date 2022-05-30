package main //import "github.com/Golang-Tools/jwthelper/v2/rsa-generator"
import (
	"os"

	"github.com/Golang-Tools/jwthelper/v2/cmd/createkey"
	"github.com/Golang-Tools/jwthelper/v2/cmd/jwtsigner_serv"
	"github.com/Golang-Tools/jwthelper/v2/cmd/jwtverifier_serv"
	log "github.com/Golang-Tools/loggerhelper/v2"
	s "github.com/Golang-Tools/schema-entry-go/v2"
)

func main() {
	root, err := s.NewEntryPoint(s.WithName("jwthelper"), s.WithUsage("jwthelper createkey|signer|verifier [options] "))
	if err != nil {
		log.Error("init root node err", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	createkey, err := s.NewEndPoint(new(createkey.CreateKey), s.WithName("createkey"), s.WithUsage("jwthelper createkey [options]"))
	if err != nil {
		log.Error("create createkey node get error", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	signer, err := s.NewEndPoint(new(jwtsigner_serv.Server), s.WithName("signer"), s.WithUsage("jwthelper signer [options]"))
	if err != nil {
		log.Error("create signer node get error", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	verifier, err := s.NewEndPoint(new(jwtverifier_serv.Server), s.WithName("verifier"), s.WithUsage("jwthelper verifier [options]"))
	if err != nil {
		log.Error("create verifier node get error", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	verifier.SetParent(root)
	createkey.SetParent(root)
	signer.SetParent(root)
	root.Parse(os.Args)
}
