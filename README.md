# harpo

`harpo` is a tool and library that provides the following functionality:

* Given a [seed phrase](https://en.bitcoin.it/wiki/Seed_phrase), it can
generate any number of
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

### Creation

In order to create secret-shared seed phrases, run the following command:

```
harpo create --num-shares [N] --threshold [T] (--file [F] | --interactive)
```

The input is provided in one of two ways:
* Using the `--file` option, providing the path `[F]` to the file containing
the space-delimited seed phrase
* Using the `--interactive` flag, providing the seed phrase on the command line.

For example, the content of the file or input provided interactively may be:

```
cat swing flag economy stadium alone churn speed unique patch report train
```

Note that the input seed phrase must be
[BIP-0039](https://en.bitcoin.it/wiki/BIP_0039) compliant, otherwise
reconstruction is likely to fail.

Apart from specifying the input source, two other parameters are required:

* The desired number `[N]` of secret-shared seed phrases must be provided.
* The desired threshold `[T]`, i.e., the minimum number of secret-shared seed
phrases required to reconstruct the original seed phrase, must be provided.

The created seed phrases are written to standard output.

### Reconstruction

In order to reconstruct the original seed phrase, run the following command:

```
harpo reconstruct (--file [F] | --interactive)
```

Again, the input is provided in one of two ways:
* Using the `--file` option, providing the path `[F]` to the file containing
the space-delimited seed phrases, one seed phrase per line.
* Using the `--interactive` flag, providing the seed phrases on the command
line, one after the other.

The reconstructed seed phrase is written to standard output.
If at least `[T]` secret-shared seed phrases are provided, the output will
match the original seed phrase. Otherwise, the output is indistinguishable from
a random seed phrase.

## Development

The tool is under active development. While the basic functionality is complete,
it still must be tested more thoroughly.

Several additional sub-commands, options, and flags will be added
at a later point in time.
