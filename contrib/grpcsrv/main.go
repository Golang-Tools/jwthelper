// jwthelper 服务端CLI入口,提供 createkey|signer|verifier 三个子命令
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/Golang-Tools/jwthelper/contrib/grpcsrv/createkey"
	"github.com/Golang-Tools/jwthelper/contrib/grpcsrv/signerserv"
	"github.com/Golang-Tools/jwthelper/contrib/grpcsrv/verifierserv"
	log "github.com/Golang-Tools/loggerhelper/v4"
	s "github.com/Golang-Tools/schema-entry-go/v4"
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
	signer, err := s.NewEndPoint(signerserv.NewServer(), s.WithName("signer"), s.WithUsage("jwthelper signer [options]"))
	if err != nil {
		log.Error("create signer node get error", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	verifier, err := s.NewEndPoint(verifierserv.NewServer(), s.WithName("verifier"), s.WithUsage("jwthelper verifier [options]"))
	if err != nil {
		log.Error("create verifier node get error", log.Dict{"err": err.Error()})
		os.Exit(2)
	}
	verifier.SetParent(root)
	createkey.SetParent(root)
	signer.SetParent(root)
	err = root.Parse(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if !errors.Is(err, s.ErrHelp) {
			os.Exit(1)
		}
	}
}
