package web

import (
	"context"
	"errors"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
)

const masterKeySentinelMeta = "um-c.master-key-sentinel.v1"

var (
	// ErrMasterKeyMismatch means the supplied master key cannot open the
	// database's auth sentinel/TOTP state. Authentication must fail closed.
	ErrMasterKeyMismatch = errors.New("web: master key does not match auth database")
	// ErrMasterKeyUninitialized means an existing auth database has encrypted TOTP
	// state but no sentinel. An operator must run the local explicit key-init path
	// after verifying the key; startup must not rewrite/auth-bypass it.
	ErrMasterKeyUninitialized = errors.New("web: auth database master-key sentinel is not initialized")
)

func masterKeySentinelAAD() []byte { return []byte("um-c:master-key-sentinel:v1") }
func masterKeySentinelPlain() []byte {
	return []byte("um-c master key sentinel v1")
}

// VerifyMasterKey proves the supplied key matches the database auth sentinel.
// On a brand-new auth database with no encrypted TOTP state it initializes the
// sentinel. An upgraded database with TOTP state but no sentinel fails closed
// until the operator runs the explicit local key-init command.
func VerifyMasterKey(ctx context.Context, st *store.Store, key []byte) error {
	if st == nil || len(key) != umcauth.MasterKeyBytes {
		return ErrMasterKeyMismatch
	}
	sealed, err := st.GetAuthMeta(ctx, masterKeySentinelMeta)
	if err == nil {
		if _, openErr := umcauth.Open(key, sealed, masterKeySentinelAAD()); openErr != nil {
			return ErrMasterKeyMismatch
		}
		return nil
	}
	if !errors.Is(err, store.ErrAuthMetaNotFound) {
		return err
	}
	secrets, err := st.ListEncryptedTOTPSecrets(ctx)
	if err != nil {
		return err
	}
	if len(secrets) > 0 {
		return ErrMasterKeyUninitialized
	}
	// Once any account exists, initializing a sentinel automatically could bind a
	// wrong-but-valid key to an upgraded database. Require the explicit local
	// key-init path for any existing account; only a completely fresh auth
	// database auto-initializes.
	users, err := st.CountAuthUsers(ctx)
	if err != nil {
		return err
	}
	if users > 0 {
		return ErrMasterKeyUninitialized
	}
	blob, err := umcauth.Seal(key, masterKeySentinelPlain(), masterKeySentinelAAD())
	if err != nil {
		return ErrMasterKeyMismatch
	}
	inserted, err := st.SetAuthMetaIfAbsent(ctx, masterKeySentinelMeta, blob, time.Now().Unix())
	if err != nil {
		return err
	}
	if inserted {
		return nil
	}
	// Lost a concurrent initialization race; verify the winner's sentinel.
	sealed, err = st.GetAuthMeta(ctx, masterKeySentinelMeta)
	if err != nil {
		return err
	}
	if _, err := umcauth.Open(key, sealed, masterKeySentinelAAD()); err != nil {
		return ErrMasterKeyMismatch
	}
	return nil
}

// InitializeMasterKeyForExistingDB is the explicit local upgrade path. It first
// cryptographically verifies the key against every existing encrypted TOTP
// secret, then writes the sentinel. It never rotates/replaces an existing
// sentinel and never discards TOTP state.
func InitializeMasterKeyForExistingDB(ctx context.Context, st *store.Store, key []byte) error {
	if st == nil || len(key) != umcauth.MasterKeyBytes {
		return ErrMasterKeyMismatch
	}
	if sealed, err := st.GetAuthMeta(ctx, masterKeySentinelMeta); err == nil {
		if _, openErr := umcauth.Open(key, sealed, masterKeySentinelAAD()); openErr != nil {
			return ErrMasterKeyMismatch
		}
		return nil
	} else if !errors.Is(err, store.ErrAuthMetaNotFound) {
		return err
	}
	secrets, err := st.ListEncryptedTOTPSecrets(ctx)
	if err != nil {
		return err
	}
	for _, row := range secrets {
		if _, err := umcauth.Open(key, row.Secret, []byte("umc-totp:"+row.UserID+":v1")); err != nil {
			return ErrMasterKeyMismatch
		}
	}
	blob, err := umcauth.Seal(key, masterKeySentinelPlain(), masterKeySentinelAAD())
	if err != nil {
		return ErrMasterKeyMismatch
	}
	inserted, err := st.SetAuthMetaIfAbsent(ctx, masterKeySentinelMeta, blob, time.Now().Unix())
	if err != nil {
		return err
	}
	if inserted {
		return nil
	}
	sealed, err := st.GetAuthMeta(ctx, masterKeySentinelMeta)
	if err != nil {
		return err
	}
	if _, err := umcauth.Open(key, sealed, masterKeySentinelAAD()); err != nil {
		return ErrMasterKeyMismatch
	}
	return nil
}
