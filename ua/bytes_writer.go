// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import "io"

// A Writer implements the io.Writer, io.WriterAt
// interfaces by writing to a byte slice.
// Unlike a Buffer, a Writer is write-only.
type Writer struct {
	s []byte
	i int // current writing index
}

// NewWriter returns a new Writer writing to b.
func NewWriter(b []byte) *Writer { return &Writer{b, 0} }

// Len returns the number of bytes of the written portion of the slice.
func (w *Writer) Len() int {
	return int(w.i)
}

// Size returns the original length of the underlying byte slice.
// The returned value is always the same and is not affected by calls
// to any other method.
func (w *Writer) Size() int64 { return int64(len(w.s)) }

// Write copies slice p to buffer, returning the number of bytes written.
func (w *Writer) Write(p []byte) (n int, err error) {
	if w.i >= len(w.s) {
		return 0, io.ErrShortWrite
	}
	d := w.s[w.i:]
	n = copy(d, p)
	w.i += n
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// WriteAt copies slice p to buffer, at a given offset from start,
// returning the number of bytes written. Only useful to overwrite bytes
// in buffer already written to by Write(). Does not affect the index that Write()
// uses, and therefore does not change the length of slice returned by Bytes().
func (w *Writer) WriteAt(p []byte, offset int64) (n int, err error) {
	if int(offset) >= w.i {
		return 0, io.ErrShortWrite
	}
	d := w.s[offset:]
	n = copy(d, p)
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// Bytes returns a slice of length b.Len() holding the written portion of the buffer.
// The slice is valid for use only until the next buffer modification (that is,
// only until the next call to a method like Write).
// The slice aliases the buffer content at least until the next buffer modification,
// so immediate changes to the slice will affect the result of future reads.
func (w *Writer) Bytes() []byte { return w.s[:w.i] }
