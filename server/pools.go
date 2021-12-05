// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"sync"

	"github.com/djherbis/buffer"
)

// bytesPool is a pool of byte slices
var bytesPool = sync.Pool{New: func() interface{} { s := make([]byte, defaultBufferSize); return &s }}

// bufferPool is a pool of buffers
var bufferPool = buffer.NewMemPoolAt(int64(defaultBufferSize))
