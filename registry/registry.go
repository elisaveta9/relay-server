package registry

import (
	"relay/device"
	"sync"
)

type Registry struct {
	Mu      sync.Mutex
	Domains map[string]*device.Device
}

var Global = &Registry{
	Domains: make(map[string]*device.Device),
}
