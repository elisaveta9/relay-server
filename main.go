package main

import (
	"context"
	"log"
	"os"

	"relay/admin"
	"relay/grpcserver"
	"relay/ingress"
	"relay/storage"
	"relay/tlsutil"
)

func main() {
	admin.ApiKey = os.Getenv("SECRET_API_KEY")
	if admin.ApiKey == "" {
		log.Fatal("SECRET_API_KEY is not set")
	}
	admin.EnrollmentToken = os.Getenv("RELAY_ENROLLMENT_TOKEN")
	if admin.EnrollmentToken == "" {
		log.Println("RELAY_ENROLLMENT_TOKEN is not set; device enrollment endpoint is disabled")
	}

	dbDSN := os.Getenv("DATABASE_URL")
	if dbDSN == "" {
		dbDSN = os.Getenv("RELAY_DATABASE_DSN")
	}
	if dbDSN == "" {
		log.Fatal("DATABASE_URL or RELAY_DATABASE_DSN is not set")
	}

	db, err := storage.OpenPostgres(dbDSN)
	if err != nil {
		log.Fatal(err)
	}
	if err := storage.AutoMigrate(context.Background(), db); err != nil {
		log.Fatal(err)
	}
	repo := storage.NewRepository(db)

	tlsCfg, err := tlsutil.GRPCTLSConfig()
	if err != nil {
		log.Fatal(err)
	}

	admin.InitLogger()

	go admin.Serve(":8443", repo)
	go grpcserver.Serve(":50051", tlsCfg, repo)

	ingress.Listen(":443")
}
