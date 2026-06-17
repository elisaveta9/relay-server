package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"relay/logfile"
)

const (
	logsMaxBytes     int64 = 256 * 1024
	logsDefaultLines       = 200
	logsMaxLines           = 1000
)

func logsV1Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		source := r.URL.Query().Get("source")
		var logPath string
		switch source {
		case "admin":
			logPath = "admin.log"
			source = "admin"
		default:
			logPath = "server.log"
			source = "server"
		}

		maxLines := logsDefaultLines
		if n, err := strconv.Atoi(r.URL.Query().Get("lines")); err == nil && n > 0 {
			if n > logsMaxLines {
				n = logsMaxLines
			}
			maxLines = n
		}

		data, err := logfile.TailFile(logPath, logsMaxBytes)
		if err != nil {
			http.Error(w, "cannot read log file", http.StatusInternalServerError)
			return
		}

		lines := splitLogLines(data, maxLines)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"source": source,
			"lines":  lines,
			"count":  len(lines),
		})
	}
}

func splitLogLines(data []byte, maxLines int) []string {
	if len(data) == 0 {
		return []string{}
	}

	parts := strings.Split(string(data), "\n")
	lines := make([]string, 0, len(parts))
	for _, line := range parts {
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines
}
