// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
)

func Run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Println("Usage: lunaris managed --data-dir DIR\n       lunaris config <show|list|draft-from|apply|operations> [options]\n       lunaris backup --data-dir DIR --output FILE\n       lunaris restore --data-dir EMPTY_DIR --input FILE\n       lunaris admin <setup-token|reset-password> --data-dir DIR [--password-file FILE]\n       lunaris keygen [reality|vless]\n       lunaris version\n       lunaris serve [--config bootstrap.yaml] (webui build)\nProxy configuration is stored in SQLite and edited through the JSON management API.\nSignals in managed mode (Linux/macOS): SIGHUP applies the saved draft; SIGUSR1 logs status.")
		return nil
	}
	switch args[0] {
	case "run", "check":
		return errors.New("node YAML commands have been removed; use serve to configure SQLite through the JSON API, or managed to run committed configuration")
	case "serve":
		return serve(ctx, args[1:])
	case "managed":
		return runManaged(ctx, args[1:])
	case "admin":
		return runAdmin(ctx, args[1:])
	case "config":
		return runConfig(ctx, args[1:])
	case "backup":
		return runBackup(ctx, args[1:], false)
	case "restore":
		return runBackup(ctx, args[1:], true)
	case "keygen":
		if len(args) == 2 && (args[1] == "reality" || args[1] == "vless") {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			private, public := base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			values := map[string]string{"private_key": private, "public_key": public}
			if args[1] == "vless" {
				values = map[string]string{"decryption": "mlkem768x25519plus.native.600s." + private, "encryption": "mlkem768x25519plus.native.1rtt." + public}
			}
			result, _ := json.Marshal(values)
			fmt.Println(string(result))
			return nil
		}
		if len(args) != 1 {
			return fmt.Errorf("usage: keygen [reality|vless]")
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
