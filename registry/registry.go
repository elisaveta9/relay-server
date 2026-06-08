package registry

import (
	"relay/device"
	"sync"
)

type Registry struct {
	Mu      sync.RWMutex
	Domains map[string]*device.Device
	Devices map[*device.Device]struct{}
}

var Global = &Registry{
	Domains: make(map[string]*device.Device),
	Devices: make(map[*device.Device]struct{}),
}

func (r *Registry) RegisterDevice(dev *device.Device) {
	if dev == nil {
		return
	}
	r.Mu.Lock()
	defer r.Mu.Unlock()
	if r.Devices == nil {
		r.Devices = make(map[*device.Device]struct{})
	}
	r.Devices[dev] = struct{}{}
}

func (r *Registry) UnregisterDevice(dev *device.Device) {
	if dev == nil {
		return
	}
	r.Mu.Lock()
	defer r.Mu.Unlock()
	delete(r.Devices, dev)
}

func (r *Registry) DevicesSnapshot() []*device.Device {
	r.Mu.RLock()
	defer r.Mu.RUnlock()

	seen := make(map[*device.Device]struct{}, len(r.Devices)+len(r.Domains))
	devices := make([]*device.Device, 0, len(r.Devices))
	for dev := range r.Devices {
		if dev != nil {
			seen[dev] = struct{}{}
			devices = append(devices, dev)
		}
	}
	for _, dev := range r.Domains {
		if dev == nil {
			continue
		}
		if _, ok := seen[dev]; ok {
			continue
		}
		seen[dev] = struct{}{}
		devices = append(devices, dev)
	}
	return devices
}

func (r *Registry) Bind(domain string, dev *device.Device) (*device.Device, bool) {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	previous, existed := r.Domains[domain]
	r.Domains[domain] = dev
	return previous, existed
}

func (r *Registry) Get(domain string) (*device.Device, bool) {
	r.Mu.RLock()
	defer r.Mu.RUnlock()
	dev, ok := r.Domains[domain]
	return dev, ok
}

func (r *Registry) Unbind(domain string) (*device.Device, bool) {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	dev, ok := r.Domains[domain]
	if ok {
		delete(r.Domains, domain)
	}
	return dev, ok
}

func (r *Registry) UnbindDevice(dev *device.Device) []string {
	r.Mu.Lock()
	defer r.Mu.Unlock()

	domains := make([]string, 0)
	for domain, activeDev := range r.Domains {
		if activeDev == dev {
			delete(r.Domains, domain)
			domains = append(domains, domain)
		}
	}
	return domains
}
