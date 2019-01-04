package main

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

const privKeyPEM = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBQPgWbVBetaMxzKvgn4jiU6nfFH5M3rO82KoygX9adCgAAAKizS+c5s0vn
OQAAAAtzc2gtZWQyNTUxOQAAACBQPgWbVBetaMxzKvgn4jiU6nfFH5M3rO82KoygX9adCg
AAAECAAxHrkDWce7vt4CEm9HelgKoH1RuwTGmXKvNUoWX1y1A+BZtUF61ozHMq+CfiOJTq
d8Ufkzes7zYqjKBf1p0KAAAAHmdlb3JnZXRhbmtlcnNsZXl0cmF2ZWxAcGVuZ3VpbgECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----
`

const pubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFA+BZtUF61ozHMq+CfiOJTqd8Ufkzes7zYqjKBf1p0K test@comment"

func TestSSHSign(t *testing.T) {
	// Bizarre SSH signing format
	edSigner, err := ssh.ParsePrivateKey([]byte(privKeyPEM))
	if err != nil {
		t.Fatal(err)
	}

	// EdDSA actually doesn't use randomness at all
	signature, err := edSigner.Sign(rand.Reader, []byte("Hello, world"))
	if err != nil {
		t.Fatal(err)
	}

	// Extract a normal key for a normal person
	edKey, err := ssh.ParseRawPrivateKey([]byte(privKeyPEM))
	if err != nil {
		t.Fatal(err)
	}

	privKey, ok := edKey.(*ed25519.PrivateKey)
	if !ok {
		t.Fatal("couldn't cast key")
	}

	edSig := ed25519.Sign(*privKey, []byte("Hello, world"))

	if !bytes.Equal(signature.Blob, edSig) {
		t.Fatal("shit is wack")
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pubKey.Marshal()[19:], []byte(privKey.Public().(ed25519.PublicKey))) {
		t.Fatal("should get the same pubkey!")
	}

	frankenSig := &ssh.Signature{
		Format: signature.Format,
		Blob:   edSig,
	}

	err = pubKey.Verify([]byte("Hello, world"), frankenSig)
	if err != nil {
		t.Fatal(err)
	}
}
