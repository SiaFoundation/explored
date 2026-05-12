---
default: patch
---

# Cache host metrics

#323 by @chris124567

We are getting spammed with log messages about HostMetrics taking 50-100ms.  This PR cache the results and invalidates when we get new host scans to avoid this problem.  There are alternatives to the approach here, but because we compute medians instead of means (see #175) they are generally a bit ugly.  We could also periodically store snapshots of the host metrics in the database and have HostMetrics simply retrieve the latest one.  I don't feel too strongly either way.

```
DEBUG   sqlite3.transaction.rows        slow next       {"id": "bee57ec1", "attempt": 1, "elapsed": "64.314065ms", "stack": "go.sia.tech/explored/persist/sqlite.(*rows).Next\n\tgo.sia.tech/explored/persist/sqlite/sql.go:57\ngo.sia.tech/explored/persist/sqlite.(*Store).HostMetrics.func3\n\tgo.sia.tech/explored/persist/sqlite/metrics.go:65\ngo.sia.tech/explored/persist/sqlite.doTransaction\n\tgo.sia.tech/explored/persist/sqlite/store.go:91\ngo.sia.tech/explored/persist/sqlite.(*Store).transaction\n\tgo.sia.tech/explored/persist/sqlite/store.go:37\ngo.sia.tech/explored/persist/sqlite.(*Store).HostMetrics\n\tgo.sia.tech/explored/persist/sqlite/metrics.go:55\ngo.sia.tech/explored/explorer.(*Explorer).HostMetrics\n\tgo.sia.tech/explored/explorer/explorer.go:337\ngo.sia.tech/explored/api.(*server).hostMetricsHandler\n\tgo.sia.tech/explored/api/server.go:296\ngo.sia.tech/jape.Mux.adaptor.func1\n\tgo.sia.tech/jape@v0.14.1/server.go:185\ngithub.com/julienschmidt/httprouter.(*Router).ServeHTTP\n\tgithub.com/julienschmidt/httprouter@v1.3.0/router.go:387\nmain.runRootCmd.func1\n\tgo.sia.tech/explored/cmd/explored/main.go:313\nnet/http.HandlerFunc.ServeHTTP\n\tnet/http/server.go:2286\nnet/http.serverHandler.ServeHTTP\n\tnet/http/server.go:3311\nnet/http.(*conn).serve\n\tnet/http/server.go:2073"}
```
