package umcauth

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// fastPasswordParams keeps unit tests fast; production defaults are exercised
// separately.
func fastPasswordParams() PasswordParams {
	return PasswordParams{Memory: 8 * 1024, Time: 1, Parallelism: 1}
}

var passwordFormatRE = regexp.MustCompile(`^\$argon2id\$v=19\$m=8192,t=1,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
var defaultPasswordFormatRE = regexp.MustCompile(`^\$argon2id\$v=19\$m=65536,t=3,p=2\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)

func TestPasswordHashVerifyRoundTrip(t *testing.T) {
	params := fastPasswordParams()
	for _, password := range []string{
		"correct horse battery staple",
		"123456789012",
		"密码密码密码密",
		" leading and trailing spaces ",
		"a",
	} {
		encoded, err := HashPassword(password, params)
		if err != nil {
			t.Fatalf("HashPassword(%q): %v", password, err)
		}
		if !passwordFormatRE.MatchString(encoded) {
			t.Fatalf("HashPassword(%q) = %q, want fixed Argon2id format", password, encoded)
		}
		ok, err := VerifyPassword(encoded, password)
		if err != nil {
			t.Fatalf("VerifyPassword(%q): %v", password, err)
		}
		if !ok {
			t.Fatalf("VerifyPassword(%q) = false, want true", password)
		}
		wrong := password + "x"
		ok, err = VerifyPassword(encoded, wrong)
		if err != nil {
			t.Fatalf("VerifyPassword(wrong) returned error: %v", err)
		}
		if ok {
			t.Fatalf("VerifyPassword(%q) = true, want false", wrong)
		}
	}
}

func TestPasswordHashDefaultParams(t *testing.T) {
	params := DefaultPasswordParams()
	if params.Memory != 64*1024 || params.Time != 3 || params.Parallelism != 2 {
		t.Fatalf("DefaultPasswordParams() = %+v, want 64 MiB/3/2", params)
	}
	encoded, err := HashPassword("correct horse battery staple", params)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !defaultPasswordFormatRE.MatchString(encoded) {
		t.Fatalf("default-parameter hash %q does not match the documented format", encoded)
	}
	parsed, err := ParsePasswordParams(encoded)
	if err != nil {
		t.Fatalf("ParsePasswordParams: %v", err)
	}
	if parsed != params {
		t.Fatalf("ParsePasswordParams() = %+v, want %+v", parsed, params)
	}
	ok, err := VerifyPassword(encoded, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("VerifyPassword(default hash) = %v, %v; want true, nil", ok, err)
	}
}

func TestPasswordSaltIsFresh(t *testing.T) {
	params := fastPasswordParams()
	first, err := HashPassword("correct horse battery staple", params)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	second, err := HashPassword("correct horse battery staple", params)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if first == second {
		t.Fatal("two hashes of the same password are identical; salt is not random")
	}
	if strings.Contains(first, "correct horse") || strings.Contains(second, "correct horse") {
		t.Fatal("encoded hash contains the plaintext password")
	}
}

func TestPasswordParamsValidate(t *testing.T) {
	cases := []struct {
		name    string
		params  PasswordParams
		wantErr bool
	}{
		{"default", DefaultPasswordParams(), false},
		{"minimum", PasswordParams{Memory: 8 * 1024, Time: 1, Parallelism: 1}, false},
		{"max parallelism", PasswordParams{Memory: 128 * 1024, Time: 10, Parallelism: 16}, false},
		{"memory too low", PasswordParams{Memory: 4 * 1024, Time: 1, Parallelism: 1}, true},
		{"memory too high", PasswordParams{Memory: 1024*1024 + 1, Time: 1, Parallelism: 1}, true},
		{"time zero", PasswordParams{Memory: 8 * 1024, Time: 0, Parallelism: 1}, true},
		{"time too high", PasswordParams{Memory: 8 * 1024, Time: 11, Parallelism: 1}, true},
		{"parallelism zero", PasswordParams{Memory: 8 * 1024, Time: 1, Parallelism: 0}, true},
		{"parallelism too high", PasswordParams{Memory: 8 * 1024, Time: 1, Parallelism: 17}, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.params.Validate()
			if (err != nil) != testCase.wantErr {
				t.Fatalf("Validate(%+v) error = %v, wantErr %v", testCase.params, err, testCase.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidPasswordParams) {
				t.Fatalf("Validate error = %v, want ErrInvalidPasswordParams", err)
			}
		})
	}
}

func TestPasswordHashRejectsInvalidParams(t *testing.T) {
	for _, params := range []PasswordParams{
		{},
		{Memory: 1, Time: 1, Parallelism: 1},
		{Memory: 8 * 1024, Time: 0, Parallelism: 1},
		{Memory: 1024 * 1024, Time: 11, Parallelism: 1},
	} {
		if _, err := HashPassword("correct horse battery staple", params); !errors.Is(err, ErrInvalidPasswordParams) {
			t.Fatalf("HashPassword(%+v) error = %v, want ErrInvalidPasswordParams", params, err)
		}
	}
}

func TestParsePasswordHashStrict(t *testing.T) {
	valid, err := HashPassword("correct horse battery staple", fastPasswordParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	parts := strings.Split(valid, "$")
	if len(parts) != 6 {
		t.Fatalf("unexpected encoded hash shape: %q", valid)
	}
	salt, hash := parts[4], parts[5]
	saltBytes, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		t.Fatalf("decode generated salt: %v", err)
	}
	hashBytes, err := base64.RawStdEncoding.DecodeString(hash)
	if err != nil {
		t.Fatalf("decode generated hash: %v", err)
	}
	shortSalt := base64.RawStdEncoding.EncodeToString(saltBytes[:15])
	longSalt := base64.RawStdEncoding.EncodeToString(append(append([]byte{}, saltBytes...), 0))
	shortHash := base64.RawStdEncoding.EncodeToString(hashBytes[:16])

	malformed := []string{
		"",
		strings.TrimPrefix(valid, "$"),
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt + "$" + hash + "$extra",
		"$bcrypt$v=19$m=8192,t=1,p=1$" + salt + "$" + hash,
		"$argon2i$v=19$m=8192,t=1,p=1$" + salt + "$" + hash,
		"$argon2id$v=16$m=8192,t=1,p=1$" + salt + "$" + hash,
		"$argon2id$v=019$m=8192,t=1,p=1$" + salt + "$" + hash,
		"$argon2id$v=19$t=1,m=8192,p=1$" + salt + "$" + hash,
		"$argon2id$v=19$m=8192,t=1$" + salt + "$" + hash,
		"$argon2id$v=19$m=8192,t=1,p=1,x=1$" + salt + "$" + hash,
		"$argon2id$v=19$m=08192,t=1,p=1$" + salt + "$" + hash,
		"$argon2id$v=19$m=8192,t=01,p=1$" + salt + "$" + hash,
		"$argon2id$v=19$m=8192,t=1,p=0$" + salt + "$" + hash,
		"$argon2id$v=19$m=1048577,t=1,p=1$" + salt + "$" + hash,
		"$argon2id$v=19$m=4294967296,t=1,p=1$" + salt + "$" + hash,
		"$argon2id$v=19$m=8192,t=1,p=1$" + shortSalt + "$" + hash,
		"$argon2id$v=19$m=8192,t=1,p=1$" + longSalt + "$" + hash,
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt + "$" + shortHash,
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt + "= $ " + hash,
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt + "==$" + hash,
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt + "x$" + hash,
		" $" + strings.TrimPrefix(valid, "$"),
		valid + " ",
	}
	for _, encoded := range malformed {
		if _, err := ParsePasswordParams(encoded); err == nil {
			t.Fatalf("ParsePasswordParams(%q) = nil error, want error", encoded)
		}
		if ok, err := VerifyPassword(encoded, "correct horse battery staple"); err == nil || ok {
			t.Fatalf("VerifyPassword(%q) = %v, %v; want false, error", encoded, ok, err)
		}
	}
}

func TestParsePasswordParamsValid(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple", fastPasswordParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	params, err := ParsePasswordParams(encoded)
	if err != nil {
		t.Fatalf("ParsePasswordParams: %v", err)
	}
	if params != fastPasswordParams() {
		t.Fatalf("ParsePasswordParams() = %+v, want %+v", params, fastPasswordParams())
	}
}

func TestValidatePasswordPolicy(t *testing.T) {
	cases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"empty", "", true},
		{"eleven bytes", "12345678901", true},
		{"twelve bytes", "123456789012", false},
		{"1024 bytes", strings.Repeat("a", 1024), false},
		{"1025 bytes", strings.Repeat("a", 1025), true},
		{"four three-byte runes", "密码密码密码密", false},
		{"400 three-byte runes", strings.Repeat("密", 400), true},
		{"NUL byte", "12345678901\x00", true},
		{"invalid UTF-8", string([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4}), true},
		{"control only", strings.Repeat("\x01", 12), true},
		{"spaces only", strings.Repeat(" ", 12), true},
		{"mixed control and printable", "abc\x01defghijk", false},
		{"newline in passphrase", "correct horse\nbattery", false},
		{"passphrase", "correct horse battery staple", false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := ValidatePasswordPolicy(testCase.password)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("ValidatePasswordPolicy(%q) error = %v, wantErr %v", testCase.password, err, testCase.wantErr)
			}
			if err != nil && !errors.Is(err, ErrPasswordPolicy) {
				t.Fatalf("error = %v, want ErrPasswordPolicy", err)
			}
		})
	}
}

func TestPasswordErrorsDoNotContainSecret(t *testing.T) {
	secret := "correct horse battery staple"
	if _, err := HashPassword(secret, PasswordParams{}); err == nil {
		t.Fatal("HashPassword(invalid params) returned nil error")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("error contains the password: %v", err)
	}
	encoded, err := HashPassword(secret, fastPasswordParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := VerifyPassword(encoded[:len(encoded)-2], secret); err == nil {
		t.Fatal("VerifyPassword(truncated hash) returned nil error")
	} else if strings.Contains(err.Error(), encoded) {
		t.Fatalf("error contains the encoded hash: %v", err)
	}
	if err := ValidatePasswordPolicy(secret); err != nil {
		t.Fatalf("policy rejected a valid passphrase: %v", err)
	}
	if err := ValidatePasswordPolicy("short"); err == nil || strings.Contains(err.Error(), "short") {
		t.Fatalf("policy error leaks or misses input: %v", err)
	}
}
