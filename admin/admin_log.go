package admin

import (
	"fmt"
	"log"

	"relay/logfile"
)

var adminLogger *log.Logger

func InitLogger() error {
	f, err := logfile.NewRotatingWriter(
		"admin.log",
		logfile.DefaultMaxBytes,
		logfile.DefaultMaxBackups,
	)
	if err != nil {
		return fmt.Errorf("cannot open admin.log: %w", err)
	}

	adminLogger = log.New(f, "", log.LstdFlags|log.LUTC)
	return nil
}
