// Copyright 2013 Tad Glines
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package srp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"os"
	"testing"
)

func TestNewSRP(*testing.T) {
	username := []byte("example")
	password := []byte("3x@mp1e")

	srp, err := NewSRP("rfc5054.2048", sha256.New, nil)
	if err != nil {
		log.Fatal(err)
	}

	cs := srp.NewClientSession(username)
	salt, v, err := srp.ComputeVerifier(username, password)
	if err != nil {
		log.Fatal(err)
	}

	ss := srp.NewServerSession(username, salt, v)

	ckey, err := cs.ComputeKey(salt, ss.GetB(), password, false)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("The Client's computed session key is: %v\n", ckey)

	skey, err := ss.ComputeKey(cs.GetA())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("The Server's computed session key is: %v\n", skey)

	cauth := cs.ProcessClientChallenge(username, password, salt, ss.GetB(), false)
	if !ss.VerifyClientAuthenticator(cauth) {
		log.Fatal("Client Authenticator is not valid")
	}

	os.WriteFile("a.bin", cs.GetA(), 0777)
	os.WriteFile("b.bin", ss.GetB(), 0777)
	os.WriteFile("salt.bin", cs.salt, 0777)
	log.Println("m1: " + base64.StdEncoding.EncodeToString(cauth))
	sauth := ss.ComputeAuthenticator(cauth)
	if !cs.VerifyServerAuthenticator(sauth) {
		log.Fatal("Server Authenticator is not valid")
	}

	if bytes.Equal(ckey, skey) {
		log.Printf("Client's and Server's computed session key matches\n")
	} else {
		log.Fatal("Client's and Server's computed session key DOES NOT MATCH")
	}
}
