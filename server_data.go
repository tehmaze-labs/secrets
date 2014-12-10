package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/tehmaze-labs/secrets/router"
)

func getData(cfg *Config) router.HandlerFunc {
	return func(req *router.Request) (interface{}, error) {
		var secret Secret
		key := req.Params.Get("key")
		if !cfg.Storage.Data.Has(key) {
			return nil, nil
		}
		if err := cfg.Storage.Data.Get(key, &secret); err != nil {
			return nil, err
		}
		return secret, nil
	}
}

func putData(cfg *Config) router.HandlerFunc {
	return func(req *router.Request) (interface{}, error) {
		var secret Secret
		data, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &secret); err != nil {
			return nil, err
		}

		key := req.Params.Get("key")
		if err := cfg.Storage.Data.Set(key, &secret); err != nil {
			return nil, err
		}
		return map[string]string{"updated": key}, nil
	}
}
