# harpo

`harpo` is a tool and library that provides the following functionality:

* It can generate a [seed phrase](https://en.bitcoin.it/wiki/Seed_phrase).
* It can validate a given seed phrase.
* Given a valid seed phrase, it can generate any number of
[secret-shared](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) seed
phrases.
* Given sufficiently many generated seed phrases, it can reconstruct
the original seed phrase.

The `harpo` crate gets its name from
[Harpocrates](https://en.wikipedia.org/wiki/Harpocrates), the ancient god of
silence, secrecy, and confidentiality.

While `harpo` is reasonably well tested, use it **at your own risk**.

## Compilation

Make sure that [Rust](https://www.rust-lang.org/tools/install) is installed.

After cloning the repository and changing the directory to `harpo`, run the
following command:

```
cargo build --release
```

The binary can then be found under `target/release` (or `target/debug` when
running the command without the `--release` flag).

## Usage

### Generation of a Seed Phrase

A seed phrase can be generated by running the following command:

```
harpo generate --length [L]
```

The length `[L]` must be either 12, 15, 18, 21, or 24.
The generated seed phrase is written to standard output.

### Validation of a Seed Phrase

A seed phrase can be validated, i.e. checked for
[BIP-0039](https://en.bitcoin.it/wiki/BIP_0039) compliance, by running the
following command:

```
harpo validate (--file [F])
```

The input is provided in one of two ways:
* By default, the seed phrase is entered on the command line.
* When using the `--file` (`-f`) option, the space-delimited seed phrase is
read from the file at path `[F]`.

For example, the content of the file or input provided interactively may be:

```
cat swing flag economy stadium alone churn speed unique patch report train
```

### Creation of Secret-Shared Seed Phrases

In order to create secret-shared seed phrases, run the following command:

```
harpo create --num-shares [N] --threshold [T] (--file [F])
```

The input is again provided in one of two ways, on the command line or
using the `--file` (`-f`) option, in which case the space-delimited seed phrase
is read from the file at path `[F]`.

Note that the input seed phrase must pass validation, otherwise
the execution will terminate with an error message.

Apart from specifying the input source, two other parameters are required:

* `--num-shares` (`-n`) `[N]`: The desired number `[N]` of secret-shared seed
phrases must be provided. Note that the number of shares can be **at most** 16
unless the option `--no-embedding` is used (see
  [Additional Parameters](#additional-parameters)).
* `--threshold` (`-t`) `[T]`: The desired threshold `[T]`, i.e., the minimum
number of secret-shared seed phrases required to reconstruct the original
seed phrase, must be provided. The threshold must not exceed the number of
shares.

The created seed phrases are written to standard output.

### Reconstruction of a Secret-Shared Seed Phrase

In order to reconstruct the original seed phrase, run the following command:

```
harpo reconstruct (--file [F])
```

Again, the input is provided in one of two ways:
* By default, the seed phrases are entered on the command line, one after the
other.
* When using the `--file` (`-f`) option, the space-delimited seed phrases are
read from the file at path `[F]`, one seed phrase per line.

The reconstructed seed phrase is written to standard output.
If at least `[T]` secret-shared seed phrases are provided, the output will
match the original seed phrase. Otherwise, the output is indistinguishable
from a random seed phrase.

### Additional Parameters

The following additional parameters can be specified (before entering the
subcommand):

* `--verbose` (`-v`): Add this flag in order to
activate verbose output.
* `--word-list` (`-w`) `[W]`: A different word list (other than the
standard English word list) can be provided. It has to be a list of 2048
distinct words, with one word per line.

There is one optional parameter for the `create` subcommand:

* `--no-embedding` (`-N`): By default, the secret-shared seed phrases are not
BIP-0039 compliant because they encode an index that is required for the
reconstruction. In order to obtain BIP-0039 compliant seed phrases, the
embedding can be turned off using this flag. In this case, the indices must be
provided explicitly when using the `reconstruct` command. The format is
`[INDEX]: [SEED PHRASE]`.

All available parameters can be printed using the `--help` (`-h`) flag for
each subcommand.
