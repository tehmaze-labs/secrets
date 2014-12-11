package main

import (
	"fmt"
	"log"

	"github.com/tehmaze-labs/secrets/router"
)

func getGroups(cfg *Config) router.HandlerFunc {
	return func(req *router.Request) (interface{}, error) {
		var groups = []string{}
		for key := range cfg.Storage.Keys.Scan("group.") {
			groups = append(groups, key[6:])
		}
		return groups, nil
	}
}

func getGroup(cfg *Config) router.HandlerFunc {
	return func(req *router.Request) (v interface{}, err error) {
		n := req.Params.Get("name")
		k := fmt.Sprintf("group.%s", n)
		if cfg.Storage.Keys.Has(k) {
			log.Printf("group %s: list keys (%s)", n, req.RemoteAddr)
			err = cfg.Storage.Keys.Get(k, &v)
		} else {
			log.Printf("no group %q\n", n)
		}
		return
	}
}
