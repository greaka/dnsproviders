// Package inwx adapts the lego INWX DNS
// provider for Caddy. Importing this package plugs it in.
package inwx

import (
	"errors"

	"github.com/mholt/caddy/caddytls"
	"github.com/go-acme/lego/providers/dns/inwx"
)

func init() {
	caddytls.RegisterDNSProvider("inwx", NewDNSProvider)
}

// NewDNSProvider returns a new INWX DNS challenge provider.
// The credentials are interpreted as follows:
//
// len(0): use credentials from environment
// len(3): credentials[0] = Base URL
//         credentials[1] = User ID
//         credentials[2] = Key
func NewDNSProvider(credentials ...string) (caddytls.ChallengeProvider, error) {
	switch len(credentials) {
	case 0:
		return inwx.NewDNSProvider()
	case 2:
		config := inwx.NewDefaultConfig()
		config.Username = credentials[0]
		config.Password = credentials[1]
		return inwx.NewDNSProviderConfig(config)
	default:
		return nil, errors.New("invalid credentials length")
	}
}
