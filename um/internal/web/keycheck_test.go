package web_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/store"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/umcauth"
	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/web"
)

func TestUMCMasterKeySentinelAndExplicitUpgrade(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "private", "center.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	correct := make([]byte, umcauth.MasterKeyBytes)
	wrong := make([]byte, umcauth.MasterKeyBytes)
	for i := range correct {
		correct[i] = byte(i + 1)
		wrong[i] = byte(i + 2)
	}
	// A fresh DB without encrypted auth state may initialize automatically.
	if err := web.VerifyMasterKey(ctx, st, correct); err != nil {
		t.Fatalf("fresh sentinel init: %v", err)
	}
	if err := web.VerifyMasterKey(ctx, st, wrong); !errors.Is(err, web.ErrMasterKeyMismatch) {
		t.Fatalf("wrong key accepted: %v", err)
	}
	_ = st.Close()

	// Simulate an upgraded v12 database with encrypted TOTP state but no sentinel:
	// recreate a clean DB/auth state and avoid calling VerifyMasterKey.
	st2, err := store.Open(filepath.Join(dir, "private", "upgrade.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	now := time.Now().Unix()
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	user, err := st2.BootstrapAuthUser(ctx, "key-upgrade", hash, now)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := umcauth.NewTOTPSecret()
	sealed, err := umcauth.Seal(correct, []byte(secret), []byte("umc-totp:"+user.UserID+":v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.SetAuthUserTOTP(ctx, user.UserID, sealed, 1, now); err != nil {
		t.Fatal(err)
	}
	if err := web.VerifyMasterKey(ctx, st2, correct); !errors.Is(err, web.ErrMasterKeyUninitialized) {
		t.Fatalf("upgraded DB without sentinel error=%v, want uninitialized", err)
	}
	if err := web.InitializeMasterKeyForExistingDB(ctx, st2, wrong); !errors.Is(err, web.ErrMasterKeyMismatch) {
		t.Fatalf("wrong-key upgrade error=%v, want mismatch", err)
	}
	if err := web.InitializeMasterKeyForExistingDB(ctx, st2, correct); err != nil {
		t.Fatalf("correct-key upgrade: %v", err)
	}
	if err := web.VerifyMasterKey(ctx, st2, wrong); !errors.Is(err, web.ErrMasterKeyMismatch) {
		t.Fatalf("wrong key after upgrade accepted: %v", err)
	}
}

func TestUMCMasterKeyRefusesAutomaticBindingForExistingAccounts(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "private", "center.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	now := time.Now().Unix()
	hash := "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := st.BootstrapAuthUser(ctx, "existing-account", hash, now); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, umcauth.MasterKeyBytes)
	for i := range key {
		key[i] = byte(i + 9)
	}
	if err := web.VerifyMasterKey(ctx, st, key); !errors.Is(err, web.ErrMasterKeyUninitialized) {
		t.Fatalf("VerifyMasterKey(existing accounts)=%v, want ErrMasterKeyUninitialized", err)
	}
	if err := web.InitializeMasterKeyForExistingDB(ctx, st, key); err != nil {
		t.Fatalf("explicit InitializeMasterKeyForExistingDB: %v", err)
	}
	if err := web.VerifyMasterKey(ctx, st, key); err != nil {
		t.Fatalf("VerifyMasterKey after explicit init: %v", err)
	}
}
