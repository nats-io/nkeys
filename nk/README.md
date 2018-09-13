# nk - Nkeys utility program

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## SYNOPSIS

```bash
nk [-gen type] [-sign file] [-verify file] [-inkey keyfile] [-pubin keyfile] [-pubout] [-e entropy]
```

## DESCRIPTION

The nk utility program can be used to generate nkeys, signing, and verify signatures.

## COMMAND OPTIONS

-gen type

Used to create an Nkey Seed of a given type. Type can be **User**, **Account**, **Server**, **Cluster**, or **Operator**

-sign file

Used to sign the contents of file. -inkey is also required.

-verify file -sigfile sig

Used to verify a file with a given signature. -inkey or -pubin also required.

## Examples

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

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.
