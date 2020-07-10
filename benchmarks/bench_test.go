package benchmarks

import (
	"context"
	"fmt"
	"testing"

	ua "github.com/awcullen/opcua"
)

func BenchmarkPollKepware(b *testing.B) {
	// if testing.Short() {
	// 	b.Skip("skipping integration test")
	// }
	ch, err := ua.NewClient(context.Background(), "opc.tcp://0.0.0.0:49320", ua.WithInsecureSkipVerify())
	if err != nil {
		b.Error("Error opening client. " + err.Error())
		return
	}
	benchmarks := []struct {
		name     string
		tagcount int
	}{
		{"50 tags", 50},
		{"100 tags", 100},
		{"500 tags", 500},
		{"1000 tags", 1000},
		// {"2000 tags", 2000},
		// {"5000 tags", 5000},
		// {"10000 tags", 10000},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// prep taglist
			nodesToRead := make([]*ua.ReadValueID, bm.tagcount)
			for index := 0; index < bm.tagcount; index++ {
				nodesToRead[index] = &ua.ReadValueID{
					AttributeID: ua.AttributeIDValue,
					NodeID:      ua.ParseNodeID(fmt.Sprintf("ns=2;s=Simulation Examples.Functions.Sine%d", index%10)),
				}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req := &ua.ReadRequest{NodesToRead: nodesToRead}
				res, err := ch.Read(context.Background(), req)
				if err != nil {
					b.Error("Error reading. " + err.Error())
					ch.Abort(context.Background())
					return
				}
				for _, z := range res.Results {
					if z.StatusCode().IsBad() {
						b.Error("Error reading value. " + z.StatusCode().Error())
						ch.Abort(context.Background())
						return
					}
				}
			}

		})
	}
}
