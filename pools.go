// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"sync"

	"github.com/djherbis/buffer"
)

// bytesPool is a pool of byte slices
var bytesPool = sync.Pool{New: func() interface{} { return make([]byte, defaultBufferSize) }}

// bufferPool is a pool of capacity buffers
var bufferPool = buffer.NewMemPoolAt(int64(defaultBufferSize))
