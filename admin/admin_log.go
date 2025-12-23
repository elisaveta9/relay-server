package admin

import (
	"log"
	"os"
)

var adminLogger *log.Logger

func InitLogger() {
	f, err := os.OpenFile(
		"admin.log",
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if err != nil {
		log.Fatal("cannot open admin.log:", err)
	}

	adminLogger = log.New(f, "", log.LstdFlags|log.LUTC)
}
