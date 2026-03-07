package main

import (
	"net/http"
	"os"

	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

func main() {
	// Parse configuration from CLI args (same as stock smokescreen)
	conf, err := cmd.NewConfiguration(os.Args, nil)
	if err != nil {
		panic(err)
	}

	// Override RoleFromRequest: always return "default-client" so that
	// the ACL default rule applies (no TLS client certs needed).
	conf.RoleFromRequest = func(r *http.Request) (string, error) {
		return "default-client", nil
	}

	// Start the smokescreen server using the standard entry point
	quit := make(chan interface{})
	smokescreen.StartWithConfig(conf, quit)
}
