package main

import "github.com/tehmaze-labs/secrets/router"

func getIndex(req *router.Request) (interface{}, error) {
	return map[string]string{
		"/group/": "overview of all groups",
		"/node/":  "overview of all nodes",
	}, nil
}

func getNodes(cfg *Config) router.HandlerFunc {
	return func(req *router.Request) (interface{}, error) {
		var nodes = map[string][]byte{}
		for k := range cfg.Storage.Keys.Scan("group.") {
			var v map[string][]byte
			if err := cfg.Storage.Keys.Get(k, &v); err == nil {
				for node, key := range v {
					nodes[node] = key
				}
			}
		}
		return nodes, nil
	}
}
