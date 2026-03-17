package main

import (
	"log"
	"os"

	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

// Minimal Smokescreen wrapper that removes the TLS client-certificate
// requirement so plain-HTTP CONNECT requests are accepted from the sandbox.
func main() {
	conf, err := cmd.NewConfiguration(os.Args[1:], nil)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Accept every request as the same logical role.
	conf.RoleFromRequest = func(_ *smokescreen.Config, _ interface{}) (string, error) {
		return "sandbox", nil
	}

	if err := cmd.StartWithConfig(conf, nil); err != nil {
		log.Fatalf("smokescreen: %v", err)
	}
}
