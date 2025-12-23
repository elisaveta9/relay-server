package util

import "sync"

var BufPool = sync.Pool{
	New: func() any {
		return make([]byte, 4096)
	},
}
