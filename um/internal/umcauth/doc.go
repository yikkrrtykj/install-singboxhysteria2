// Package umcauth implements the UM-C authentication and secret-protection
// primitives: Argon2id password hashing, RFC 6238 TOTP, an AES-256-GCM
// master-key vault, one-time recovery codes, opaque session/CSRF tokens and a
// cryptographic Cloudflare Access JWT verifier.
//
// The package is deliberately small and dependency-light. It performs no
// logging, never puts secret material (passwords, hashes, TOTP secrets, access
// tokens, claims, master keys or plaintext) into error values or exported
// structs, and fails closed on malformed or unauthenticated input. Callers own
// persistence, session state, rate limiting and audit; the primitives below
// only answer cryptographic questions.
package umcauth
