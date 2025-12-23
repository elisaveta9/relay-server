package util

import "relay/device"

func Keys(m map[string]*device.Device) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
