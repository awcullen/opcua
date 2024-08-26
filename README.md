![robot][1]

# opcua - [![Godoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/mod/github.com/awcullen/opcua) [![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/awcullen/opcua/master/LICENSE)
Browse, read, write and subscribe to the live data published by the OPC UA servers on your network.

This package supports OPC UA TCP transport protocol with secure channel and binary encoding.  For more information, visit https://reference.opcfoundation.org/v104/.


## Includes Client and Server

To *connect* to an OPC UA server, start here [![Godoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/mod/github.com/awcullen/opcua/client)

To *create* your own OPC UA server, start here [![Godoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/mod/github.com/awcullen/opcua/server)

## Recent News
Benchmark shows this package **10X faster** than Gopcua/opcua to encode a typical payload to the network.  
```
pkg: github.com/awcullen/opcua/cmd/benchmark
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkGopcuaEncode
BenchmarkGopcuaEncode-4     	  120178	      9332 ns/op	    2536 B/op	      97 allocs/op
BenchmarkAwcullenEncode
BenchmarkAwcullenEncode-4   	 1728259	       859.3 ns/op	     154 B/op	       4 allocs/op
PASS
```


 [1]: robot6.jpg
