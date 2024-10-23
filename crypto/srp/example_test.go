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
	"encoding/hex"
	"log"
	"os"
	"testing"
)

func TestOtherSRP(*testing.T) {
	salt := "XvrHTLep84Ip2gugxuyKxw=="
	saltB, _ := base64.StdEncoding.DecodeString(salt)
	b := "l0CoBgHHTbTkgwqhMUxIdQ4ntUQHqd36O9XLj8FAxleG65mTZaP0qBDuuPIMtrnixHpexIkym9bvCmMClCVSZ7fuCwK73Pq45R70CczmFupmq/qpq8RXvaZR3DL6RgAVGGDtwRhF0ctTcN3qMg+6w4akL6DW1snfvIbwCLRF0mVQu6ohoj5jwlfMkpq2tXPy+a7FEnHr764eXp8w1ZCxAm9Pe7ChWWzPa/pfBCHIIY+d61pTLnhbN9DLlMC32bT7XKVx9r002sv8Js/a3Sk7E47Rw8aMROlj2AWDtd7YjUU25P8K+XubS6YRydmc/NqIprqfhpSoQZMRXt14zla+9w=="
	bB, _ := base64.StdEncoding.DecodeString(b)
	a := "qexvrgeM6tJETp8UD3p0BxNZbn44Q1DjCXn5BIIhDQlWBV0Lx4ZIMTNc1auTEibfKop88hyOA72qNYkqQEcWhAN0n3f1a5Sgtfd6q1B4xsOG8n+q+hrqFNZagC1LGFUKTOBqcTK8Rkq3r+pUPRL7/Y/3+oaQ9Ne8H49FV508iiHWfMZu4alG6ft0g5DPu6m0lYll+OD37oobWptB7KOnn8wsVXmD5r2mUg3WwLzau+oFKEMiswys5BB156oT+Q7z7cssuq/fLvvmM3/Uy74xN7KDFaxiwSdjgLoHYIpumSWza9Gu/BUeeCjNm3QD6oEc1xKyRXTa+sef4YB4JLMa5g=="
	aB, _ := base64.StdEncoding.DecodeString(a)

	srp, err := NewSRP("rfc5054.2048", sha256.New, nil)
	if err != nil {
		log.Fatal(err)
	}

	cs := srp.NewClientSession([]byte("username"), aB)
	m1 := cs.ProcessClientChallenge([]byte("username"), []byte("password"), saltB, bB, true)
	if hex.EncodeToString(m1) != "4accb16f0a3c21044f44609128b5c1d78f91ff2cb6fb8d3c40e3f46412f20de8" {
		log.Fatal("incorrect SRP implementation !")
	}
}

func TestNewSRP(*testing.T) {
	username := []byte("example")
	password := []byte("3x@mp1e")

	srp, err := NewSRP("rfc5054.2048", sha256.New, nil)
	if err != nil {
		log.Fatal(err)
	}

	cs := srp.NewClientSession(username, nil)
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
