# NKEYS

A public-key signature system based on [Ed25519](https://ed25519.cr.yp.to/) for the NATS ecosystem.

## About

The NATS ecosystem will be moving to [Ed25519](https://ed25519.cr.yp.to/) keys for identity, authentication and authorization for entities such as Accounts, Users, Servers and Clusters.

Ed25519 is fast and resistant to side channel attacks. Generation of a seed key is all that is needed to be stored and kept safe, as the seed can generate both the public and private keys.

The NATS system will utilize Ed25519 keys, meaning that NATS systems will never store or even have access to any private keys. Authentication will utilize a random challenge response mechanism.

Dealing with 32 byte and 64 byte raw keys can be challenging. NKEYS is designed to formulate keys in a much friendlier fashion and references work done in cryptocurrencies, specifically [Stellar](https://www.stellar.org/).	Bitcoin and others used a form of Base58 (or Base58Check) to endode raw keys. Stellar utilized a more traditonal Base32 with a CRC16 and a version or prefix byte. NKEYS utilizes a similar format where the prefix will be 1 byte for public and private keys and will be 2 bytes for seeds. The base32 encoding of these prefixes will yield friendly human readbable prefixes, e.g. '**N**' = server, '**C**' = cluster, '**A**' = account, and '**U**' = user. '**P**' is used for private keys. For seeds, the first encoded prefix is '**S**', and the second character will be the type for the public key, e.g. "**SU**" is a seed for a user key pair, "**SA**" is a seed for an account key pair.

## Installation

Use the `go` command:

	$ go get github.com/nats-io/nkeys

## Basic Usage
```go

// Create a new User
user, _ := CreateUser(nil) // Can supply an io.Reader for RND.

// Access the seed, only thing that needs to be stored and kept safe.
// seed = "SUxxxxx.."
seed, _ := user.Seed()

// Access the public key
// publicKey = "Uxxxxx.."
publicKey, _ := user.PublicKey()

// Access the private key
// privateKey = "Pxxxxx.."
privateKey, _ = user.PrivateKey()

// Create a full User who can sign and verify verify from a private seed.
user, _ = FromSeed(seed)

// Sign some data with a full key pair
data := []byte("Hello World")
sig, _ := user.Sign(data)

// Create a User who can only verify via public key only.
user, _ = FromPublicKey(publicKey)

// Verify the signature
err = user.Verify(data, sig)

```

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.
