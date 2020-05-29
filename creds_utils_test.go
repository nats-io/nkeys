package nkeys

import (
	"bytes"
	"testing"
)

func Test_ParseDecoratedJWTBad(t *testing.T) {
	v, err := ParseDecoratedJWT([]byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	if v != "foo" {
		t.Fatal("unexpected input was not returned")
	}
}

func Test_ParseDecoratedSeedBad(t *testing.T) {
	if _, err := ParseDecoratedNKey([]byte("foo")); err == nil {
		t.Fatal("Expected error")
	} else if err.Error() != "no nkey seed found" {
		t.Fatal(err)
	}
}

const (
	credsSeed      = `SUAOTBNEUHZDFJT3EUMELT7MQTP24JF3XVCXQNDSCU74G5IU6VAJBKH5LI`
	credsJwt       = `eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJHVDROVU5NRUY3Wk1XQ1JCWFZWVURLUVQ2WllQWjc3VzRKUlFYRDNMMjRIS1VKRUNRSDdRIiwiaWF0IjoxNTkwNzgxNTkzLCJpc3MiOiJBQURXTFRISUNWNFNVQUdGNkVLTlZFVzVCQlA3WVJESUJHV0dHSFo1SkJET1FZQTdHVUZNNkFRVSIsIm5hbWUiOiJPUEVSQVRPUiIsInN1YiI6IlVERTZXVEdMVFRQQ1JKUkpDS0JKUkdWTlpUTElWUjdMRUVFTFI0Q1lXV1dCS0pTN1hZSUtYRFVVIiwibmF0cyI6eyJwdWIiOnt9LCJzdWIiOnt9LCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.c_XQT04wEoVVNDRjPHeKwe17BOrSpQTcftwIbB7KoNEIz6peZCJDc4-J3emVepHofUOWy7IAo9TlLwYhuGHWAQ`
	decoratedCreds = `-----BEGIN NATS USER JWT-----
eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJHVDROVU5NRUY3Wk1XQ1JCWFZWVURLUVQ2WllQWjc3VzRKUlFYRDNMMjRIS1VKRUNRSDdRIiwiaWF0IjoxNTkwNzgxNTkzLCJpc3MiOiJBQURXTFRISUNWNFNVQUdGNkVLTlZFVzVCQlA3WVJESUJHV0dHSFo1SkJET1FZQTdHVUZNNkFRVSIsIm5hbWUiOiJPUEVSQVRPUiIsInN1YiI6IlVERTZXVEdMVFRQQ1JKUkpDS0JKUkdWTlpUTElWUjdMRUVFTFI0Q1lXV1dCS0pTN1hZSUtYRFVVIiwibmF0cyI6eyJwdWIiOnt9LCJzdWIiOnt9LCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.c_XQT04wEoVVNDRjPHeKwe17BOrSpQTcftwIbB7KoNEIz6peZCJDc4-J3emVepHofUOWy7IAo9TlLwYhuGHWAQ
------END NATS USER JWT------

************************* IMPORTANT *************************
NKEY Seed printed below can be used to sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
SUAOTBNEUHZDFJT3EUMELT7MQTP24JF3XVCXQNDSCU74G5IU6VAJBKH5LI
------END USER NKEY SEED------

*************************************************************
`
)

func Test_ParseDecoratedSeedAndJWT(t *testing.T) {
	// test with and without \r\n
	for _, creds := range [][]byte{[]byte(decoratedCreds),
		bytes.ReplaceAll([]byte(decoratedCreds), []byte{'\n'}, []byte{'\r', '\n'})} {
		kp, err := ParseDecoratedUserNKey(creds)
		if err != nil {
			t.Fatal(err)
		}
		pu, err := kp.Seed()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pu, []byte(credsSeed)) {
			t.Fatal("seeds don't match")
		}

		kp, err = ParseDecoratedNKey(creds)
		if err != nil {
			t.Fatal(err)
		}
		pu, err = kp.Seed()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pu, []byte(credsSeed)) {
			t.Fatal("seeds don't match")
		}

		jwt, err := ParseDecoratedJWT(creds)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal([]byte(jwt), []byte(credsJwt)) {
			t.Fatal("jwt don't match")
		}
	}
}
