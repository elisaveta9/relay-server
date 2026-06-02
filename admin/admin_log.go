package admin

import (
	"log"

	"relay/logfile"
)

var adminLogger *log.Logger

func InitLogger() {
	f, err := logfile.NewRotatingWriter(
		"admin.log",
		logfile.DefaultMaxBytes,
		logfile.DefaultMaxBackups,
	)
	if err != nil {
		log.Fatal("cannot open admin.log:", err)
	}

	adminLogger = log.New(f, "", log.LstdFlags|log.LUTC)
}
