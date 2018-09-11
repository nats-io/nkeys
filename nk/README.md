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
SUAHLNHIFX6MQ2TW5LCELSEWQK6NLV4T4QKP45OLEQUVWWQVM5PNXBTGCWKMHDH3L7UY5Y7PFYGBZCSIO2U6QY5QSVEI27B3HY5Q7MNVLHVA2
```

You can obtain the public key for an nkey seed as follows.

```bash
> nk -inkey user.seed -pubout > user.pub
> cat user.pub
UBTBLFGDRT5V72MO4PXS4DA4RJEHNKPIMOYJKSENPQ5T4OYPWG2VSMZT
```

Signing the contents of a file

```bash
> cat > some.txt
Hello World!

> nk -sign some.txt -inkey user.seed > some.sig
> cat some.sig
ZtD-kBrNlB8zjGY8lpvBhyW08OTP3uzM1qk7DfJSbKhbZ4iBJN52o-_NNc_Kdi7iQhfoR6nWWKrEWB2_ygnfBA
```

Verifying a signature. You can use the seed or the public key.

```bash
> nk -verify some.txt -sigfile some.sig -inkey user.seed
verification succeeded

> nk -verify some.txt -sigfile some.sig -pubin user.pub
verification succeeded
```

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.
