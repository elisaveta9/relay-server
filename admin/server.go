package admin

import (
	"log"
	"net/http"
	"relay/storage"
)

func Serve(addr string, repo *storage.Repository) {
	mux := http.NewServeMux()

	mux.Handle("/domains", requireAPIKey(http.HandlerFunc(domainsHandler(repo))))
	ServeAPIv1(mux, repo)

	enrollHandler, err := newEnrollmentHandler("certs/ca.crt", "certs/ca.key")
	if err != nil {
		log.Fatal("cannot initialize enrollment handler:", err)
	}
	mux.Handle("/enroll", enrollHandler)

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
