// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime/debug"
)

func Run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Println("Usage: lunaris run --config node.yaml\n       lunaris check --config node.yaml\n       lunaris managed --data-dir DIR [--source node.yaml]\n       lunaris config <import|show|list|draft-from|apply|operations> [options]\n       lunaris backup --data-dir DIR --output FILE\n       lunaris restore --data-dir EMPTY_DIR --input FILE\n       lunaris keygen [reality]\n       lunaris version\n       lunaris serve [--config bootstrap.yaml] (webui build)\nSignals in run/managed mode (Linux/macOS): SIGHUP applies config; SIGUSR1 logs status.")
		return nil
	}
	switch args[0] {
	case "run":
		return runNode(ctx, args[1:], false)
	case "check":
		return runNode(ctx, args[1:], true)
	case "serve":
		return serve(ctx, args[1:])
	case "managed":
		return runManaged(ctx, args[1:])
	case "config":
		return runConfig(ctx, args[1:])
	case "backup":
		return runBackup(ctx, args[1:], false)
	case "restore":
		return runBackup(ctx, args[1:], true)
	case "keygen":
		if len(args) == 2 && args[1] == "reality" {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			result, _ := json.Marshal(map[string]string{"private_key": base64.RawURLEncoding.EncodeToString(key.Bytes()), "public_key": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())})
			fmt.Println(string(result))
			return nil
		}
		if len(args) != 1 {
			return fmt.Errorf("usage: keygen [reality]")
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
