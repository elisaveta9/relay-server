package admin

import (
	"net/http"
	"strings"

	"relay/device"
	tunnelpb "relay/proto/tunnel"
	"relay/registry"
)

func domainsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {

	case "GET":
		registry.Global.Mu.Lock()
		defer registry.Global.Mu.Unlock()
		for d := range registry.Global.Domains {
			w.Write([]byte(d + "\n"))
		}

	case "POST":
		domain := strings.ToLower(r.URL.Query().Get("domain"))
		if domain == "" {
			http.Error(w, "domain required", http.StatusBadRequest)
			return
		}

		registry.Global.Mu.Lock()
		if _, exists := registry.Global.Domains[domain]; exists {
			w.Write([]byte("already registered\n"))
		} else {
			registry.Global.Domains[domain] = nil
			adminLogger.Printf(
				"ADMIN ADD domain=%s ip=%s",
				domain, r.RemoteAddr,
			)
			w.Write([]byte("registered\n"))
		}
		registry.Global.Mu.Unlock()

	case "DELETE":
		domain := strings.ToLower(r.URL.Query().Get("domain"))

		var dev *device.Device
		var existed bool

		registry.Global.Mu.Lock()
		if d, ok := registry.Global.Domains[domain]; ok {
			existed = true
			dev = d
			delete(registry.Global.Domains, domain)
		}
		registry.Global.Mu.Unlock()

		if existed && dev != nil {
			dev.SendFrame(&tunnelpb.Frame{
				Type:    tunnelpb.FrameType_FRAME_BIND_REJECTED,
				Payload: []byte(domain),
			})
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
