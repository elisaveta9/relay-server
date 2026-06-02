package logfile

import (
	"fmt"
	"os"
	"sync"
)

const (
	DefaultMaxBytes   int64 = 100 * 1024 * 1024
	DefaultMaxBackups       = 5
)

type RotatingWriter struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
	file       *os.File
	size       int64
}

func NewRotatingWriter(path string, maxBytes int64, maxBackups int) (*RotatingWriter, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxBackups < 0 {
		maxBackups = DefaultMaxBackups
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("stat log file: %w; close log file: %v", err, closeErr)
		}
		return nil, err
	}

	return &RotatingWriter{
		path:       path,
		maxBytes:   maxBytes,
		maxBackups: maxBackups,
		file:       file,
		size:       info.Size(),
	}, nil
}

func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return 0, fmt.Errorf("log file is closed")
	}

	if w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}

	err := w.file.Close()
	w.file = nil
	return err
}

func (w *RotatingWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}

	if w.maxBackups == 0 {
		if err := os.Remove(w.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		if err := os.Remove(backupPath(w.path, w.maxBackups)); err != nil && !os.IsNotExist(err) {
			return err
		}
		for i := w.maxBackups - 1; i >= 1; i-- {
			oldPath := backupPath(w.path, i)
			newPath := backupPath(w.path, i+1)
			if _, err := os.Stat(oldPath); err == nil {
				if err := os.Rename(oldPath, newPath); err != nil {
					return err
				}
			} else if !os.IsNotExist(err) {
				return err
			}
		}
		if _, err := os.Stat(w.path); err == nil {
			if err := os.Rename(w.path, backupPath(w.path, 1)); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w.file = file
	w.size = 0
	return nil
}

func backupPath(path string, index int) string {
	return fmt.Sprintf("%s.%d", path, index)
}
