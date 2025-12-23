package admin

import (
	"log"
	"net/http"
)

func Serve(addr string) {
	mux := http.NewServeMux()

	mux.Handle("/domains", requireAPIKey(http.HandlerFunc(domainsHandler)))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "admin.html")
	})

	log.Println("Admin API listening on", addr)
	log.Fatal(http.ListenAndServeTLS(
		addr,
		"certs/admin.crt",
		"certs/admin.key",
		mux,
	))
}
