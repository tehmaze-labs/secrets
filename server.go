package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tehmaze-labs/secrets/router"
)

type Handler struct {
	Config *Config
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	/*
		    w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("This is an example server.\n"))
	*/
	var reply interface{}
	var err error

	switch req.Method {
	case "GET":
		switch {
		case req.URL.Path == "/group/":
			var groups = []string{}
			for key := range h.Config.Storage.Keys.Scan("group.") {
				groups = append(groups, key[6:])
			}
			reply = groups
		case strings.HasPrefix(req.URL.Path, "/group/"):
			n := strings.SplitN(req.URL.Path, "/", 4)[2]
			k := fmt.Sprintf("group.%s", n)
			if h.Config.Storage.Keys.Has(k) {
				err = h.Config.Storage.Keys.Get(k, &reply)
			} else {
				log.Printf("no group %q\n", n)
			}
		}
	}

	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
	} else if reply == nil {
		w.WriteHeader(404)
		w.Write([]byte("Not found"))
	} else {
		out, err := json.MarshalIndent(&reply, "", "  ")
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
		} else {
			w.Header().Set("Content-Type", "text/plain")
			w.Write(out)
		}
	}
}

type Server struct {
	http.Server
	Config *Config
	Router *router.Router
}

func ListenAndServeTLS(cfg *Config) error {
	rt := router.NewRouter()
	rt.GET("/", getIndex)
	rt.GET("/group/", getGroups(cfg))
	rt.GET("/group/:name/", getGroup(cfg))
	rt.GET("/group/:name/data/", getGroupDatas(cfg))
	rt.GET("/group/:name/data/:key/", getGroupData(cfg))
	rt.PUT("/group/:name/data/:key/", putGroupData(cfg))
	rt.GET("/node/", getNodes(cfg))
	sv := &Server{
		Config: cfg,
	}
	sv.Addr = cfg.Server.Bind
	sv.Handler = rt
	return sv.ListenAndServeTLS()
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

func (srv *Server) ListenAndServeTLS() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{srv.Config.Server.Certificate},
		NextProtos:   []string{"http/1.1"},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    srv.Config.Server.Root,
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" {
		host, err = os.Hostname()
		if err != nil {
			return err
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Printf("server: listening on https://%s:%s/\n", host, port)
	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
	return srv.Serve(tlsListener)
}
