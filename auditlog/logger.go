package auditlog

import (
	"fmt"
	"log"
	"sync"

	"relay/logfile"
)

var (
	loggerMu sync.RWMutex
	logger   *log.Logger
)

func Init() error {
	writer, err := logfile.NewRotatingWriter(
		"admin.log",
		logfile.DefaultMaxBytes,
		logfile.DefaultMaxBackups,
	)
	if err != nil {
		return fmt.Errorf("cannot open admin.log: %w", err)
	}

	loggerMu.Lock()
	logger = log.New(writer, "", log.LstdFlags|log.LUTC)
	loggerMu.Unlock()
	return nil
}

func Printf(format string, args ...any) {
	loggerMu.RLock()
	current := logger
	loggerMu.RUnlock()
	if current != nil {
		current.Printf(format, args...)
	}
}
