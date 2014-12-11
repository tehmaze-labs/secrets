package router

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

type HandlerFunc func(req *Request) (interface{}, error)

type Params map[string]string

func (p Params) Get(name string) string {
	return p[name]
}

type Request struct {
	*http.Request
	Params Params
}

type Route struct {
	Path, Method string
	matcher      *regexp.Regexp
	params       []string
	handler      HandlerFunc
}

func (r *Route) Handle(req *Request) (interface{}, error) {
	return r.handler(req)
}

func (r *Route) Match(url string) (Params, bool) {
	matches := r.matcher.FindStringSubmatch(url)
	if len(matches) == 0 {
		return nil, false
	}
	if len(r.params) == 0 {
		return nil, true
	}
	var params = make(Params, len(r.params))
	matches = matches[1:]
	for i, match := range matches {
		var name = r.params[i]
		params[name] = string(match)
	}
	return params, true
}

func NewRoute(pattern, method string, handler HandlerFunc) *Route {
	matcher, params := toMatcher(pattern)
	return &Route{
		Method:  method,
		matcher: matcher,
		params:  params,
		handler: handler,
	}
}

type Router struct {
	Routes []*Route
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := &Request{Request: r}
	var invalidMethod bool
	for _, route := range rt.Routes {
		var ok bool
		req.Params, ok = route.Match(req.URL.Path)
		if ok {
			if route.Method == req.Method {
				var status = 200
				i, err := route.Handle(req)
				if err != nil {
					status = 500
					i = map[string]string{"error": err.Error()}
				}
				if i == nil {
					status = 404
					i = map[string]string{"error": "not found"}
				}

				d, err := json.MarshalIndent(i, "", "  ")
				if err != nil {
					status = 500
					w.WriteHeader(status)
					w.Write([]byte("error: " + err.Error()))
				} else {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(status)
					w.Write(d)
				}
				return
			} else {
				invalidMethod = true
			}
		}
	}

	// Resource was not found
	if invalidMethod {
		w.WriteHeader(406)
		w.Write([]byte(`{"error": "invalid method"}`))
	} else if !strings.HasSuffix(r.URL.Path, "/") {
		w.Header().Set("Location", r.URL.Path+"/")
		w.WriteHeader(302)
	} else {
		w.WriteHeader(404)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(`{"error": "not found"}`))
	}
}

func NewRouter() *Router {
	return &Router{
		Routes: []*Route{},
	}
}

func (rt *Router) GET(pattern string, handler HandlerFunc) {
	rt.Routes = append(rt.Routes, NewRoute(pattern, "GET", handler))
}

func (rt *Router) POST(pattern string, handler HandlerFunc) {
	rt.Routes = append(rt.Routes, NewRoute(pattern, "POST", handler))
}

func (rt *Router) PUT(pattern string, handler HandlerFunc) {
	rt.Routes = append(rt.Routes, NewRoute(pattern, "PUT", handler))
}

func toMatcher(pattern string) (*regexp.Regexp, []string) {
	var paths = []string{}
	var param = []string{}
	var empty = false
	for _, part := range strings.Split(strings.TrimPrefix(pattern, "/"), "/") {
		empty = false
		switch {
		case len(part) == 0:
			empty = true
		case part[0] == ':':
			paths = append(paths, `/([^/]+)`)
			param = append(param, part[1:])
		case part[0] == '*':
			paths = append(paths, `/(.*)`)
			param = append(param, part[1:])
		default:
			paths = append(paths, "/"+part)
		}
	}
	// If the last fragment was empty, add a trailing slash
	if empty {
		paths = append(paths, "/")
	}

	var express = `^` + strings.Join(paths, "") + `$`
	var matcher = regexp.MustCompile(express)
	return matcher, param
}
