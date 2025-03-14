package leaf

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gopasspw/gopass/internal/config"
	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/internal/queue"
	"github.com/gopasspw/gopass/internal/store"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/debug"
)

// Copy will copy one entry to another location. Multi-store copies are
// supported. Each entry has to be decoded and encoded for the destination
// to make sure it's encrypted for the right set of recipients.
func (s *Store) Copy(ctx context.Context, from, to string) error {
	// recursive copy?
	if s.IsDir(ctx, from) {
		return fmt.Errorf("recursive operations are not supported")
	}

	// try direct copy first
	err := s.directMove(ctx, from, to, false)
	if err == nil {
		debug.Log("direct copy %s -> %s successful", from, to)

		return nil
	}

	debug.Log("direct copy failed: %v", err)

	content, err := s.Get(ctx, from)
	if err != nil {
		return fmt.Errorf("failed to get %q from store: %w", from, err)
	}

	if err := s.Set(ctxutil.WithCommitMessage(ctx, fmt.Sprintf("Copied from %s to %s", from, to)), to, content); err != nil {
		if !errors.Is(err, store.ErrMeaninglessWrite) {
			return fmt.Errorf("failed to save secret %q to store: %w", to, err)
		}
		out.Warningf(ctx, "No need to write: the secret is already there and with the right value")
	}

	return nil
}

// Move will move one entry from one location to another.
// Moving an entry will decode it from the old location, encode it
// for the destination store with the right set of recipients and remove it
// from the old location afterwards.
func (s *Store) Move(ctx context.Context, from, to string) error {
	// recursive move?
	if s.IsDir(ctx, from) {
		return fmt.Errorf("recursive operations are not supported")
	}

	// try direct move first
	err := s.directMove(ctx, from, to, true)
	if err == nil {
		debug.Log("direct move %s -> %s successful", from, to)

		return nil
	}

	debug.Log("direct move failed: %v", err)

	// fall back to copy and delete
	content, err := s.Get(ctx, from)
	if err != nil {
		return fmt.Errorf("failed to decrypt %q: %w", from, err)
	}

	if err := s.Set(ctxutil.WithCommitMessage(ctx, fmt.Sprintf("Move from %s to %s", from, to)), to, content); err != nil {
		if !errors.Is(err, store.ErrMeaninglessWrite) {
			return fmt.Errorf("failed to save secret %q to store: %w", to, err)
		}
		out.Warningf(ctx, "No need to write: the secret is already there and with the right value")
	}

	if err := s.Delete(ctx, from); err != nil {
		return fmt.Errorf("failed to delete %q: %w", from, err)
	}

	return nil
}

func (s *Store) directMove(ctx context.Context, from, to string, del bool) error {
	ctx = ctxutil.WithCommitMessage(ctx, fmt.Sprintf("Move from %s to %s", from, to))
	pFrom := s.Passfile(from)
	pTo := s.Passfile(to)

	// if original destination has trailing slash,
	// it means we should create folder and move/copy source file in it
	if strings.HasSuffix(to, "/") {
		// Check if the destination already exists as a file
		if s.storage.Exists(ctx, to) && !s.storage.IsDir(ctx, to) {
			return fmt.Errorf("destination %q already exists as a file", to)
		}
		pTo = filepath.Join(to, filepath.Base(pFrom))
	}

	debug.Log("directMove %s (%q) -> %s (%q)", from, to, pFrom, pTo)

	if err := s.storage.Move(ctx, pFrom, pTo, del); err != nil {
		return fmt.Errorf("failed to move %q to %q: %w", from, to, err)
	}

	// It is not possible to perform concurrent git add and git commit commands
	// so we need to skip this step when using concurrency and perform them
	// at the end of the batch processing.
	if IsNoGitOps(ctx) {
		debug.Log("sub.directMove(%q -> %q) - skipping git ops (disabled)", from, to)

		return nil
	}

	if err := s.storage.TryAdd(ctx, pFrom, pTo); err != nil {
		return fmt.Errorf("failed to add %q and %q to git: %w", pFrom, pTo, err)
	}

	if !ctxutil.IsGitCommit(ctx) {
		return nil
	}

	// try to enqueue this task, if the queue is not available
	// it will return the task and we will execute it inline
	t := queue.GetQueue(ctx).Add(func(_ context.Context) (context.Context, error) {
		return nil, s.gitCommitAndPush(ctx, to)
	})

	_, err := t(ctx)

	return err
}

// Delete will remove an single entry from the store.
func (s *Store) Delete(ctx context.Context, name string) error {
	return s.delete(ctx, name, false)
}

// Prune will remove a subtree from the Store.
func (s *Store) Prune(ctx context.Context, tree string) error {
	return s.delete(ctx, tree, true)
}

// delete will either delete one file or an directory tree depending on the
// recurse flag.
func (s *Store) delete(ctx context.Context, name string, recurse bool) error {
	path := s.Passfile(name)

	if recurse {
		if err := s.deleteRecurse(ctx, name, path); err != nil {
			return err
		}
	}
	if err := s.deleteSingle(ctx, path); err != nil {
		// might fail if we deleted the root of a tree which isn't a secret
		// itself
		if !recurse {
			return err
		}
	}

	if !ctxutil.IsGitCommit(ctx) {
		return nil
	}

	if err := s.storage.TryCommit(ctx, fmt.Sprintf("Remove %s from store.", name)); err != nil {
		return fmt.Errorf("failed to commit changes to git: %w", err)
	}

	if !config.Bool(ctx, "core.autopush") {
		debug.Log("not pushing to git remote, core.autopush is false")

		return nil
	}

	if err := s.storage.TryPush(ctx, "", ""); err != nil {
		return fmt.Errorf("failed to push change to git remote: %w", err)
	}

	return nil
}

func (s *Store) deleteRecurse(ctx context.Context, name, path string) error {
	if !s.storage.IsDir(ctx, name) && !s.storage.Exists(ctx, path) {
		return store.ErrNotFound
	}

	name = strings.TrimPrefix(name, string(filepath.Separator))

	debug.Log("Pruning %s", name)
	if err := s.storage.Prune(ctx, name); err != nil {
		debug.Log("storage.Prune(%v) failed", name)

		return err
	}

	if err := s.storage.TryAdd(ctx, name); err != nil {
		return fmt.Errorf("failed to add %q to git: %w", path, err)
	}
	debug.Log("pruned")

	return nil
}

func (s *Store) deleteSingle(ctx context.Context, path string) error {
	if !s.storage.Exists(ctx, path) {
		return store.ErrNotFound
	}

	debug.Log("Deleting %s", path)
	if err := s.storage.Delete(ctx, path); err != nil {
		return err
	}

	if err := s.storage.TryAdd(ctx, path); err != nil {
		return fmt.Errorf("failed to add %q to git: %w", path, err)
	}

	return nil
}
