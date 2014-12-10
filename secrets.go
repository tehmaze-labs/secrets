package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
)

var config *Config

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "testdata/secrets.conf", "configuration file")

	config = NewConfig()
	if err := config.Load(configFile); err != nil {
		log.Fatalf("config: %v", err)
	}

	for name, group := range config.Group {
		log.Printf("loaded group %q: %s\n", name, strings.Join(group.ACLs, ","))

		var k = fmt.Sprintf("group.%s", name)
		var v map[string][]byte
		if config.Storage.Keys.Has(k) {
			if err := config.Storage.Keys.Get(k, &v); err != nil {
				panic(err)
			}
		} else {
			v = map[string][]byte{}
		}
		for hostname, pub := range group.Keys {
			v[hostname] = pub
		}
		if err := config.Storage.Keys.Set(k, v); err != nil {
			panic(err)
		}
	}

	log.Fatal(ListenAndServeTLS(config))
}
