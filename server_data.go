package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/tehmaze-labs/secrets/router"
	"github.com/tehmaze-labs/secrets/secret"
)

func getGroupData(cfg *Config) router.HandlerFunc {
	return func(req *router.Request) (interface{}, error) {
		name := req.Params["name"]
		key := fmt.Sprintf(req.Params["key"])

		group := cfg.Group[name]
		if group == nil {
			return nil, nil
		}
		log.Printf("group %s: get %q (%s)", group.Name, key, req.RemoteAddr)
		if !cfg.ACL.GroupPermitted(group, req.RemoteAddr) {
			return nil, errors.New("access denied by ACL")
		}

		if !group.Data.Has(key) {
			return nil, nil
		}

		var s secret.Secret
		if err := group.Data.Get(key, &s); err != nil {
			return nil, err
		}
		return s, nil
	}
}

func getGroupDatas(cfg *Config) router.HandlerFunc {
	return func(req *router.Request) (interface{}, error) {
		name := req.Params["name"]

		group := cfg.Group[name]
		if group == nil {
			return nil, nil
		}
		log.Printf("group %s: list (%s)", group.Name, req.RemoteAddr)

		var keys = []string{}
		for key := range group.Data.Scan("") {
			keys = append(keys, key)
		}
		return map[string]interface{}{"keys": keys}, nil
	}
}

func putGroupData(cfg *Config) router.HandlerFunc {
	return func(req *router.Request) (interface{}, error) {
		name := req.Params["name"]
		key := fmt.Sprintf(req.Params["key"])

		group := cfg.Group[name]
		if group == nil {
			return nil, nil
		}
		log.Printf("group %s: put %q (%s)", group.Name, key, req.RemoteAddr)
		if !cfg.ACL.GroupPermitted(group, req.RemoteAddr) {
			return nil, errors.New("access denied by ACL")
		}

		data, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		var s secret.Secret
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}

		if err := group.Data.Set(key, &s); err != nil {
			return nil, err
		}
		return map[string]string{"updated": key}, nil
	}
}
