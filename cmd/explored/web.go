package main

import (
	"net"
	"net/http"
	"strings"

	"go.sia.tech/explored/api"
)

func startWeb(l net.Listener, node *node) error {
	api := api.NewServer(node.e, node.cm, node.s)
	return http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
			api.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
}
