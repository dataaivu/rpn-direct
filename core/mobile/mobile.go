// Package mobile is the gomobile-bound surface of the engine. It deliberately
// exposes ONLY primitive-typed functions so `gomobile bind` doesn't try to
// marshal the internal protocol structs (slices of structs, json.RawMessage)
// which it cannot handle. Android calls these via the generated .aar.
package mobile

import "github.com/dataaivu/rpn-direct/core"

// Start brings the tunnel up. cfgJSON is a core.Config; tunFd comes from
// VpnService.establish(). Returns "" on success, else an error message.
func Start(cfgJSON string, tunFd int) string { return core.Start(cfgJSON, tunFd) }

// Stop tears the tunnel down.
func Stop() { core.Stop() }

// Status returns a short state string for the UI.
func Status() string { return core.Status() }
