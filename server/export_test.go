// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import "time"

// SetReverseConnectDelays sets the reconnect delays for tests and returns a func that restores them.
func SetReverseConnectDelays(min, max time.Duration) func() {
	oldMin, oldMax := reverseConnectMinDelay, reverseConnectMaxDelay
	reverseConnectMinDelay, reverseConnectMaxDelay = min, max
	return func() { reverseConnectMinDelay, reverseConnectMaxDelay = oldMin, oldMax }
}
