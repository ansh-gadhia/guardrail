package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	appvault "github.com/guardrail/guardrail/internal/app/vault"
	"github.com/guardrail/guardrail/internal/config"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/security"
	"github.com/guardrail/guardrail/internal/platform/database"
)

// runRotateKEK re-wraps every vaulted secret onto the current master key.
//
// # WHY THIS COMMAND EXISTS
//
// Rotation was implemented and unreachable. RotateKEK had no HTTP handler, no
// subcommand and no job, so the documented story — "the KEK rotates without
// touching ciphertext" — was not something an operator could actually do. Worse,
// the KEK id was the constant "env:1", so changing GUARDRAIL_MASTER_KEY produced
// a different key under the same name and every secret became permanently
// unopenable, silently.
//
// HOW A ROTATION GOES
//
//  1. Keep the old key. Move it to GUARDRAIL_MASTER_KEY_PREVIOUS.
//  2. Put the new key in GUARDRAIL_MASTER_KEY.
//  3. Run `guardrail rotate-kek`. It re-wraps every secret onto the new key.
//  4. When it reports nothing left, clear GUARDRAIL_MASTER_KEY_PREVIOUS.
//
// Only the DEK wrapping changes. The secret ciphertext, and the associated data
// bound into it, are untouched — which is why this can run while the API is up.
func runRotateKEK(args []string) error {
	fs := flag.NewFlagSet("rotate-kek", flag.ExitOnError)
	from := fs.String("from", "", "KEK id to move away from (default: the previous key, then the legacy id)")
	batch := fs.Int("batch", 100, "credentials per batch")
	dryRun := fs.Bool("dry-run", false, "report what would move and change nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	keys, err := security.NewEnvKeyProviderWithPrevious(cfg.Security.MasterKey, cfg.Security.PreviousMasterKey)
	if err != nil {
		return err
	}
	activeID, _, err := keys.Active()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	db, err := database.New(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer db.Close()

	pg := postgres.New(db.Pool)
	repo := postgres.NewCredentialRepo(pg)
	svc := appvault.NewService(repo, security.NewEnvelopeEncryptor(keys), nil)

	// Which id are we moving away from? The previous key if one is configured,
	// otherwise the legacy constant — a deployment that has never rotated has
	// every row under that and nothing else to move.
	source := *from
	if source == "" {
		source = keys.Previous()
	}
	if source == "" {
		source = security.LegacyEnvKEKID
	}
	if source == activeID {
		fmt.Printf("nothing to do: %s is already the active key\n", source)
		return nil
	}

	pending, err := repo.CountByKEK(ctx, source)
	if err != nil {
		return err
	}
	fmt.Printf("active key:  %s\n", activeID)
	fmt.Printf("moving from: %s\n", source)
	fmt.Printf("credentials: %d\n", pending)
	if pending == 0 {
		fmt.Println("nothing to move.")
		return nil
	}
	if *dryRun {
		fmt.Println("dry run: nothing was changed.")
		return nil
	}

	// The active key has to be in the registry before anything is sealed under
	// it: credentials.kek_id is a foreign key, so an unregistered id fails on
	// the constraint rather than on anything that reads like a key problem.
	if err := repo.RegisterKEK(ctx, activeID, "env"); err != nil {
		return fmt.Errorf("register the active key: %w", err)
	}

	n, stranded, err := svc.RotateKEK(ctx, source, *batch)
	if err != nil {
		// Partial progress is real progress: rows already moved are on the new
		// key and stay there. Re-running continues from where this stopped.
		fmt.Fprintf(os.Stderr, "rotated %d of %d before stopping\n", n, pending)
		return err
	}
	fmt.Printf("rotated %d credential(s) onto %s\n", n, activeID)
	if stranded > 0 {
		// Already unreadable before this ran. Named rather than hidden: it is
		// almost always data sealed under a master key that is long gone, and an
		// operator who is never told will assume the rotation was complete.
		fmt.Printf("\n%d credential(s) could not be unwrapped by this deployment's keys\n", stranded)
		fmt.Println("  they were already unreadable and were left untouched.")
		fmt.Println("  a connection using one would fail; find them with:")
		fmt.Printf("    SELECT id, name FROM credentials WHERE kek_id = '%s' AND deleted_at IS NULL;\n", source)
	}

	left, err := repo.CountByKEK(ctx, source)
	if err == nil && left == 0 && cfg.Security.PreviousMasterKey != "" {
		fmt.Println("\nnothing is left under the old key — you can now clear GUARDRAIL_MASTER_KEY_PREVIOUS.")
	}
	return nil
}
