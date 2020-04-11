# Gallisto

![Build and test
Go](https://github.com/ymarcus93/gallisto/workflows/Build%20and%20test%20Go/badge.svg?branch=master)

A Go implementation of the [Callisto
protocol](https://www.projectcallisto.org/callisto-cryptographic-approach.pdf)

This repository contains both a library implementation of the protocol (see
`protocol` folder), and an interactive CLI (see `cmd/gallisto` folder).

# Download, verify, and run

The CLI is bundled as a release. Download the latest release from
[here](https://github.com/ymarcus93/gallisto/releases)

A signed list of checksums is available to verify the authenticity of all
releases. The checksum file (`sha256sum.txt`) is signed using the following
[Minisign](https://jedisct1.github.io/minisign/) key:
`RWQiEhl2q3tjeBIvQEjWyR/i/rhJqeuCc0Qjs0tXZqL3X2c221s3Se3n`

You can verify the signature and checksums as follows:

```console
$ minisign -Vm sha256sum.txt -P RWQiEhl2q3tjeBIvQEjWyR/i/rhJqeuCc0Qjs0tXZqL3X2c221s3Se3n
$ sha256sum -c sha256sum.txt
```

Now uncompress the tar file:

```console
$ tar -xvf <name-of-release>.tar.gz
```

And run the cli:

```console
$ cd <name-of-release>
$ ./gallisto
```

# CLI usage

The CLI is bundled with a Callisto server (holder of OPRF key) and has the
functionality to spawn new Callisto clients (submitters of entries).

The CLI is stateless. When the program starts up, new keys for the server and
DLOCs/LOCs are created.

The CLI provides an interactive series of menus to execute the protocol. There
are two main actions: (1) Submit an entry, and (2) Find matches

## Submit an entry

This command walks the user through a series of questions in order to submit an
entry to the server.

When the user asks to submit a new entry, an initial Callisto client is created.
For each subsequent submission, the CLI asks if a new client should be created.

If there is more than one available clients, the CLI asks the user which client to use.

## Find matches

This command checks to see if there are any matches on submitted entries.

Recall that in the Callisto protocol, a match between entries can only be found
if more than two _distinct_ users report the same perpetrator. In this
implementation, perpetrator IDs are derived from the perpretrator's name.

For a match to be found, use the [Submit an entry](#submit-an-entry) command to
submit an entry with the same perpetrator name using distinct clients.

Once a match has been found, the CLI asks which matches to decrypt. The CLI then
uses the LOC/DLOC private keys to decrypt all entry/assignment data submitted
for the matched perpretrator.