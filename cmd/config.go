// SPDX-License-Identifier: GPL-3.0-only
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Ember-Moth/Lunaris/internal/config"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"github.com/Ember-Moth/Lunaris/internal/store/sqlite"
)

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func runConfig(ctx context.Context, args []string) (result error) {
	if len(args) == 0 {
		return errors.New("use config import, show, list, draft-from, apply or operations")
	}
	command := args[0]
	flags := flag.NewFlagSet("config "+command, flag.ContinueOnError)
	dir := flags.String("data-dir", "./data", "managed node data directory")
	var path, revision, expected, key, base string
	var limit int
	switch command {
	case "import":
		flags.StringVar(&path, "config", "", "node YAML to save as a draft")
		flags.StringVar(&expected, "expect", "", "expected draft revision (defaults to current head)")
	case "show":
		flags.StringVar(&revision, "revision", "", "revision to inspect (defaults to draft)")
	case "list", "operations":
		flags.IntVar(&limit, "limit", 20, "maximum records (1-100)")
	case "draft-from":
		flags.StringVar(&revision, "revision", "", "historical revision to copy into a new draft")
		flags.StringVar(&expected, "expect", "", "expected current draft revision")
	case "apply":
		flags.StringVar(&revision, "revision", "", "saved draft revision to apply")
		flags.StringVar(&key, "request-id", "", "idempotency key (required)")
		flags.StringVar(&base, "base", "", "optional expected committed revision")
	default:
		return fmt.Errorf("unknown config command %q", command)
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected config command arguments")
	}
	if command == "import" && path == "" {
		return errors.New("import requires --config")
	}
	if command == "draft-from" && revision == "" {
		return errors.New("draft-from requires --revision")
	}
	if command == "apply" && (revision == "" || key == "") {
		return errors.New("apply requires --revision and --request-id")
	}
	registry, err := builtin.NewRegistry()
	if err != nil {
		return err
	}
	var imported *model.RuntimeConfig
	if command == "import" {
		imported, err = config.LoadNode(path, registry)
		if err != nil {
			return err
		}
	}
	store, err := sqlite.Open(ctx, *dir)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()
	heads, err := store.Heads(ctx)
	if err != nil {
		return err
	}
	switch command {
	case "import", "draft-from":
		if command == "draft-from" {
			imported, err = store.Resolve(ctx, revision)
			if err != nil {
				return err
			}
			imported, err = registry.Normalize(imported)
			if err != nil {
				return err
			}
		}
		if expected == "" {
			expected = heads.DraftRevision
		}
		saved, err := store.SaveDraft(ctx, expected, imported)
		if err != nil {
			return err
		}
		return printJSON(saved)
	case "show":
		if revision == "" {
			revision = heads.DraftRevision
		}
		stored, err := store.Revision(ctx, revision)
		if err != nil {
			return err
		}
		return printJSON(struct {
			Heads    model.ConfigHeads    `json:"heads"`
			Revision model.ConfigRevision `json:"revision"`
		}{heads, stored})
	case "list":
		list, err := store.Revisions(ctx, limit)
		if err != nil {
			return err
		}
		return printJSON(list)
	case "operations":
		list, err := store.Operations(ctx, limit)
		if err != nil {
			return err
		}
		return printJSON(list)
	case "apply":
		service, err := config.OpenService(ctx, store, registry, false)
		if err != nil {
			return err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), service.ShutdownTimeout())
			defer cancel()
			result = errors.Join(result, service.Close(cleanup))
		}()
		op, applyErr := service.Apply(ctx, key, revision, base)
		if errors.Is(applyErr, ports.ErrIdempotencyConflict) || errors.Is(applyErr, ports.ErrConflict) {
			return applyErr
		}
		if op.ID != "" {
			return errors.Join(applyErr, printJSON(op))
		}
		return applyErr
	}
	return nil
}

func runBackup(ctx context.Context, args []string, restore bool) error {
	name := "backup"
	if restore {
		name = "restore"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	dir := flags.String("data-dir", "./data", "offline managed data directory")
	var path string
	if restore {
		flags.StringVar(&path, "input", "", "SQLite backup to restore into an empty directory")
	} else {
		flags.StringVar(&path, "output", "", "new private SQLite backup file")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if path == "" || flags.NArg() != 0 {
		return fmt.Errorf("%s requires a backup file path", name)
	}
	var err error
	if restore {
		err = sqlite.Restore(ctx, *dir, path)
	} else {
		err = sqlite.Backup(ctx, *dir, path)
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s completed\n", name)
	return nil
}
