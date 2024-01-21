# nk - Nkeys utility program

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## DESCRIPTION

The nk utility program can be used to generate nkeys, signing, and verify signatures.

## INSTALLATION

```bash
go install github.com/nats-io/nkeys/nk@latest
```

## COMMAND OPTIONS

```
Usage: nk [options]
    -v                    Show version
    -gen <type>           Generate key for [user|account|server|cluster|operator|curve|x25519]
    -sign <file>          Sign <file> with -inkey <keyfile>
    -verify <file>        Verfify <file> with -inkey <keyfile> or -pubin <public> and -sigfile <file>
    -inkey <file>         Input key file (seed/private key)
    -pubin <file>         Public key file
    -sigfile <file>       Signature file
    -pubout               Output public key
    -e                    Entropy file, e.g. /dev/urandom
    -pre <vanity>         Attempt to generate public key given prefix, e.g. nk -gen user -pre derek
    -maxpre <N>           Maximum attempts at generating the correct key prefix, default is 10,000,000
```

## EXAMPLES

Create a user keypair. The result will be an encoded seed. Seeds are prefixed with an 'S', and followed by the type, e.g. U = user.

```bash
> nk -gen user > user.seed
> cat user.seed
SUAKYRHVIOREXV7EUZTBHUHL7NUMHPMAS7QMDU3GTIUWEI5LDNOXD43IZY
```

You can obtain the public key for an nkey seed as follows.

```bash
> nk -inkey user.seed -pubout > user.pub
> cat user.pub
UD466L6EBCM3YY5HEGHJANNTN4LSKTSUXTH7RILHCKEQMQHTBNLHJJXT
```

Signing the contents of a file

```bash
> cat > some.txt
Hello World!

> nk -sign some.txt -inkey user.seed > some.sig
> cat some.sig
0CK1XmkxNfUGfudxliWTWeoETgIo23m9qowS9yTfYFSrjR8HgAW63jQ3NxPU_jG38hZPW61IZSun37N690CkDg
```

Verifying a signature. You can use the seed or the public key.

```bash
> nk -verify some.txt -sigfile some.sig -inkey user.seed
Verified OK

> nk -verify some.txt -sigfile some.sig -pubin user.pub
Verified OK
```

## LICENSE

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.
