package main

import (
	"net"
	"net/http"
	"strings"

	"go.sia.tech/explored/api"
	"go.sia.tech/jape"
)

func startWeb(l net.Listener, node *node, password string) error {
	renter := api.NewServer(node.cm, node.s)
	api := jape.BasicAuth(password)(renter)
	return http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
			api.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
}
