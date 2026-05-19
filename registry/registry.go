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

func (r *Registry) Bind(domain string, dev *device.Device) (*device.Device, bool) {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	previous, existed := r.Domains[domain]
	r.Domains[domain] = dev
	return previous, existed
}

func (r *Registry) Get(domain string) (*device.Device, bool) {
	r.Mu.Lock()
	defer r.Mu.Unlock()
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
