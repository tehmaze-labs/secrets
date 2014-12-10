package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tehmaze-labs/secrets/key"
)

func usage() {
	fmt.Printf("%s <command>\n", os.Args[0])
	println(`
commands:

    keyutil generate
    keyutil publickey <file>
`)
	os.Exit(1)
}

func main() {
	flag.Parse()

	if flag.NArg() == 0 {
		usage()
	}

	switch flag.Arg(0) {
	case "generate":
		k, err := key.NewPrivateKey()
		if err != nil {
			panic(err)
		}
		o, err := k.Marshal()
		if err != nil {
			panic(err)
		}
		fmt.Fprint(os.Stdout, string(o))
	case "publickey":
		if flag.NArg() != 2 {
			usage()
		}
		k, err := key.LoadPrivateKey(flag.Arg(1))
		if err != nil {
			if !strings.Contains(err.Error(), key.PEMPrivateKey) {
				panic(err)
			}
		} else {
			k = k.AsPublicKey()
		}
		if k == nil {
			k, err = key.LoadPublicKey(flag.Arg(1))
			if err != nil {
				panic(err)
			}
		}
		if k != nil {
			o, err := k.Marshal()
			if err != nil {
				panic(err)
			}
			fmt.Fprint(os.Stdout, string(o))
		}
	}
}
