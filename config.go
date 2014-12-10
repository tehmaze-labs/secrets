package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tehmaze-labs/secrets/key"
	"github.com/tehmaze-labs/secrets/storage"
)

func errCfgSyntax(msg string, a ...interface{}) error {
	return fmt.Errorf("syntax error: "+msg, a...)
}

// Group is the configuration for a named group.
type Group struct {
	ACLs []string
	Keys map[string][]byte
}

func NewGroup() (group *Group) {
	group = new(Group)
	group.ACLs = []string{}
	group.Keys = map[string][]byte{}
	return group
}

// configBlock holds a block of configuration options.
type configBlock interface {
	parse([]string) (configBlock, error)
}

// Config is the top-level configuration structure.
type Config struct {
	Storage struct {
		Data *storage.Storage
		Keys *storage.Storage
	}
	Server struct {
		tls.Certificate
		Bind string
		Key  *key.Key
		Root *x509.CertPool
	}
	ACL   map[string]*ACL
	Group map[string]*Group
}

// NewConfig initialises a new configuration structure.
func NewConfig() *Config {
	cfg := &Config{}
	cfg.ACL = map[string]*ACL{}
	cfg.Group = map[string]*Group{}
	cfg.Server.Root = x509.NewCertPool()
	cfg.Storage.Data = &storage.Storage{}
	cfg.Storage.Keys = &storage.Storage{}
	return cfg
}

// Load reads and parses a configuration file.
func (cfg *Config) Load(file string) (err error) {
	handle, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("error opening %q: %v", file, err)
	}
	defer handle.Close()

	var block, b configBlock
	var stack *configStack
	stack = newConfigStack()
	stack.Push(cfg)

	read := bufio.NewReader(handle)
	scan := bufio.NewScanner(read)
	scan.Split(bufio.ScanLines)

	block = cfg
	lineno := 0
	for scan.Scan() {
		line := scan.Text()
		lineno++
		//fmt.Printf("%d: block %T %v\n", lineno, block, block)
		part := strings.Fields(line)
		if len(part) == 0 || strings.HasPrefix(part[0], "#") {
			continue
		}
		b, err = block.parse(part)
		if err != nil {
			return fmt.Errorf("%s[%d]: %v", file, lineno, err)
		}
		if b == nil {
			block = stack.Pop()
			if block == nil || len(*stack) == 0 {
				return fmt.Errorf("%s[%d]: end of stack", file, lineno)
			}
		} else if b != block {
			stack.Push(block)
			block = b
		}
	}
	return cfg.Validate()
}

// Validate does post-configuration checks.
func (cfg *Config) Validate() error {
	if len(cfg.ACL) == 0 {
		return errors.New("no ACL configured")
	}
	if len(cfg.Group) == 0 {
		return errors.New("no Group configured")
	}
	for name, group := range cfg.Group {
		if len(group.ACLs) == 0 {
			return fmt.Errorf("group %q has no ACL", name)
		}
	}
	if cfg.Storage.Data.Backend == nil {
		return errors.New("no Server.Storage configured")
	}
	return nil
}

func (cfg *Config) parse(field []string) (b configBlock, err error) {
	if len(field) < 2 {
		return nil, errCfgSyntax(`expected block`)
	}
	switch field[0] {
	case "ACL":
		if len(field) != 3 || field[2] != "{" {
			return nil, errCfgSyntax(`expected: "ACL <name> {"`)
		}
		return newConfigACL(cfg, field[1]), nil
	case "Group":
		if len(field) != 3 || field[2] != "{" {
			return nil, errCfgSyntax(`expected: "Group <name> {"`)
		}
		return newConfigGroup(cfg, field[1]), nil
	case "Server":
		return newConfigServer(cfg), nil
	default:
		return nil, errCfgSyntax(`unexpected top-level token %q`, field[0])
	}
}

type configStack []configBlock

func newConfigStack() *configStack {
	s := make(configStack, 0)
	return &s
}

func (s *configStack) Push(b configBlock) {
	*s = append(*s, b)
}

func (s *configStack) Pop() configBlock {
	b := (*s)[len(*s)-1]
	*s = (*s)[0 : len(*s)-1]
	return b
}

type configACL struct {
	Config *Config
	Name   string
	ACL    *ACL
}

func newConfigACL(cfg *Config, name string) *configACL {
	acl := new(ACL)
	acl.Permits = []string{}
	acl.Rejects = []string{}
	return &configACL{
		Config: cfg,
		Name:   name,
		ACL:    acl,
	}
}

func (block *configACL) parse(field []string) (b configBlock, err error) {
	if len(field) == 1 && field[0] == "}" {
		block.Config.ACL[block.Name] = block.ACL
		return nil, nil
	}
	if len(field) < 2 {
		return nil, errCfgSyntax(`expected key value`)
	}
	switch field[0] {
	case "Permit":
		for _, pattern := range field[1:] {
			block.ACL.Permits = append(block.ACL.Permits, pattern)
		}
	case "Reject":
		for _, pattern := range field[1:] {
			block.ACL.Rejects = append(block.ACL.Rejects, pattern)
		}
	default:
		return nil, errCfgSyntax(`unexpected ACL token %q`, field[0])
	}
	return block, nil
}

type configGroup struct {
	Config  *Config
	Name    string
	ACLs    []string
	Include *key.Key
}

func newConfigGroup(cfg *Config, name string) *configGroup {
	block := &configGroup{
		Config: cfg,
		Name:   name,
	}
	block.ACLs = []string{}
	return block
}

func (block *configGroup) parse(field []string) (b configBlock, err error) {
	if len(field) == 1 && field[0] == "}" {
		block.Config.Group[block.Name] = NewGroup()
		block.Config.Group[block.Name].ACLs = block.ACLs
		if block.Include != nil {
			hostname, err := os.Hostname()
			if err != nil {
				return nil, err
			}
			block.Config.Group[block.Name].Keys[hostname] = block.Include.PublicKey
		}
		return nil, nil
	}
	if len(field) < 2 {
		return nil, errCfgSyntax(`expected key value`)
	}
	switch field[0] {
	case "ACL":
		block.ACLs = append(block.ACLs, field[1:]...)
	case "Include":
		key, err := key.Load(field[1])
		if err != nil {
			return nil, err
		}
		block.Include = key.AsPublicKey()
	default:
		return nil, errCfgSyntax(`unexpected Group token %q`, field[0])
	}
	return block, nil
}

type configServer struct {
	Config   *Config
	Storage  string
	Level    int
	Compress bool
}

func newConfigServer(cfg *Config) *configServer {
	return &configServer{
		Config: cfg,
	}
}

func (block *configServer) parse(field []string) (b configBlock, err error) {
	if len(field) == 1 && field[0] == "}" {
		if block.Storage == "" {
			return nil, errCfgSyntax(`expected Storage option`)
		}
		var storages = map[string]*storage.Storage{
			"data": block.Config.Storage.Data,
			"keys": block.Config.Storage.Keys,
		}
		for name, stor := range storages {
			opt := storage.NewOptions(filepath.Join(block.Storage, name))
			if block.Compress {
				opt.Extra["compress"] = block.Level
			}
			backend, err := storage.NewJSONBackend(opt)
			if err != nil {
				return nil, err
			}
			newstor := storage.New(backend)
			*stor = *newstor
		}

		/*
			var back storage.Backend
			// Data storage
			back, err = storage.NewJSONBackend(storage.NewOptions(filepath.Join(block.Storage, "data")))
			if err != nil {
				return nil, err
			}
			block.Config.Storage.Data = storage.New(back)
			// Groups storage
		*/
		return nil, nil
	}
	if len(field) < 2 {
		return nil, errCfgSyntax(`expected key value`)
	}
	switch field[0] {
	case "Bind":
		if len(field) != 2 {
			return nil, errCfgSyntax(`expected address`)
		}
		block.Config.Server.Bind = field[1]
	case "Deflate":
		if len(field) != 2 {
			return nil, errCfgSyntax(`expected level`)
		}
		level, err := strconv.Atoi(field[1])
		if err != nil {
			return nil, err
		}
		if level < gzip.DefaultCompression || level > gzip.BestCompression {
			return nil, fmt.Errorf("gzip: invalid compression level: %d", level)
		}
		block.Compress = true
		block.Level = level
	case "KeyPair":
		if len(field) != 3 {
			return nil, errCfgSyntax(`expected keyFile certFile`)
		}
		if block.Config.Server.Certificate, err = tls.LoadX509KeyPair(field[1], field[2]); err != nil {
			return nil, err
		}
	case "Key":
		if len(field) != 2 {
			return nil, errCfgSyntax(`expected path`)
		}
		if block.Config.Server.Key, err = key.Load(field[1]); err != nil {
			return nil, err
		}
		if !block.Config.Server.Key.IsPrivate() {
			return nil, fmt.Errorf("%s: not a private key", field[1])
		}
	case "Root":
		if len(field) < 2 {
			return nil, errCfgSyntax(`expected path`)
		}
		for _, file := range field[1:] {
			data, err := ioutil.ReadFile(file)
			if err != nil {
				return nil, err
			}
			block.Config.Server.Root.AppendCertsFromPEM(data)
		}
	case "Storage":
		if len(field) != 2 {
			return nil, errCfgSyntax(`expected path`)
		}
		block.Storage = field[1]
	default:
		return nil, errCfgSyntax(`unexpected Server token %q`, field[0])
	}
	return block, nil
}
