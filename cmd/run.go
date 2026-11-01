// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"runtime/debug"
)

func Run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Println("Usage: lunaris run --config node.yaml\n       lunaris check --config node.yaml\n       lunaris keygen\n       lunaris version\n       lunaris serve [--config bootstrap.yaml] (webui build)")
		return nil
	}
	switch args[0] {
	case "run":
		return runNode(ctx, args[1:], false)
	case "check":
		return runNode(ctx, args[1:], true)
	case "serve":
		return serve(ctx, args[1:])
	case "keygen":
		if len(args) != 1 {
			return fmt.Errorf("keygen does not accept arguments")
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(secret))
		return nil
	case "version":
		version := "dev"
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		fmt.Println("Lunaris", version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
