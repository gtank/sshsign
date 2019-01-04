// Copyright © 2019 George Tankersley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

func main() {
	var key, in, out, sig string

	var rootCmd = &cobra.Command{
		Use:   "sshign",
		Short: "It signs things with your ed25519 ssh keys.",
	}

	var signCmd = &cobra.Command{
		Use:   "sign",
		Short: "sign with an ssh-ed25519 private key",
		Run: func(cmd *cobra.Command, args []string) {
			if key == "" {
				cmd.Usage()
				return
			}
			err := sign(key, in, out)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}

	signCmd.Flags().StringVarP(&key, "key", "k", "", "ssh private key to sign with")
	signCmd.Flags().StringVarP(&in, "in", "i", "", "file to sign (default stdin)")
	signCmd.Flags().StringVarP(&out, "out", "o", "", "signature out (default stdout)")

	var verifyCmd = &cobra.Command{
		Use:   "verify",
		Short: "verify a signature with an ssh-ed25519 pubkey",
		Run: func(cmd *cobra.Command, args []string) {
			if key == "" {
				cmd.Usage()
				return
			}
			err := verify(key, in, sig)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}

	verifyCmd.Flags().StringVarP(&key, "key", "k", "", "ssh public key to verify with")
	verifyCmd.Flags().StringVarP(&in, "in", "i", "", "message to verify (default stdin)")
	verifyCmd.Flags().StringVarP(&sig, "signature", "s", "", "hex-encoded signature to verify")

	rootCmd.AddCommand(signCmd, verifyCmd)
	rootCmd.Execute()
}

func sign(key, in, out string) error {
	pem, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}

	edKey, err := ssh.ParseRawPrivateKey([]byte(pem))
	if err != nil {
		return err
	}

	privKey, ok := edKey.(*ed25519.PrivateKey)
	if !ok {
		return errors.New("couldn't cast key to ed25519.PrivateKey")
	}

	var toBeSigned []byte
	if in == "" {
		toBeSigned, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		toBeSigned, err = ioutil.ReadFile(in)
		if err != nil {
			return err
		}
	}

	edSig := ed25519.Sign(*privKey, toBeSigned)

	var outFile *os.File
	if out == "" {
		outFile = os.Stdout
	} else {
		outFile, err = os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return err
		}
	}
	defer outFile.Close()
	_, err = outFile.Write([]byte(hex.EncodeToString(edSig)))
	if err != nil {
		return err
	}
	return nil
}

func verify(key, in, sig string) error {
	pubKey, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}

	edKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return err
	}

	var toBeVerified []byte
	if in == "" {
		toBeVerified, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		toBeVerified, err = ioutil.ReadFile(in)
		if err != nil {
			return err
		}
	}

	if sig == "" {
		return errors.New("no signature file provided")
	}

	edSigEncoded, err := ioutil.ReadFile(sig)
	if err != nil {
		return err
	}

	edSigBytes := make([]byte, 64)

	_, err = hex.Decode(edSigBytes, edSigEncoded)
	if err != nil {
		return err
	}

	frankenSig := &ssh.Signature{
		Format: ssh.KeyAlgoED25519,
		Blob:   edSigBytes,
	}

	err = edKey.Verify(toBeVerified, frankenSig)
	if err != nil {
		return err
	}
	return nil
}
