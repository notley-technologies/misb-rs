# Contributing

Thanks for taking the time to help. Bug reports, fixes, support for more of the data ST 0601 carries, and documentation improvements are all welcome.

## Reporting problems

Open an issue using the bug report template. The most useful reports include:

- the version or commit you are using,
- what the decoder reported and what you expected,
- if you can share it, the KLV packet that shows the problem as a hex dump (`xxd -p packet.klv`). One packet is usually enough. Please do not attach metadata you are not allowed to share.

Security issues are different: see [SECURITY.md](SECURITY.md).

## Development

You need a stable Rust toolchain (the minimum supported version is in `Cargo.toml`: 1.70 for the library, 1.71 with the `serde` feature). For the C tests you also need a C compiler, `make`, `pkg-config` and optionally `cmake`; tests that need missing tools skip themselves.

```bash
cargo test --all-features
```

This runs the unit and integration tests, the doctests (including the Rust snippets in the README), the C ABI and install tests, and a short fuzzing pass. CI runs the same on Linux, macOS and Windows with `--locked`, plus the tests with default features, a build with warnings as errors, a check that the README's relative links resolve, checks at both minimum Rust versions, 32-bit Linux and Windows C consumers, a release throughput run and two minutes of coverage-guided fuzzing per target.

Before opening a pull request:

```bash
RUSTFLAGS="-D warnings" cargo build --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo test                # default features, without serde
```

For changes to parsing or decoding, a longer fuzz run is worth it:

```bash
MISB_FUZZ_ITERATIONS=200000 cargo test --release --test fuzz
```

If the fuzzer finds a failing input, fix the bug and add the input to `tests/fuzz_regressions/<target>/` so it is replayed from then on.

### Working on smpte-klv at the same time

The SMPTE ST 336 framing comes from [smpte-klv-rs](https://github.com/notley-technologies/smpte-klv-rs); `Cargo.toml` says where Cargo fetches it from. To change both at once, check it out next to this repository and point Cargo at it in `.cargo/config.toml`, which git ignores:

```toml
[patch."https://github.com/notley-technologies/smpte-klv-rs"]
smpte-klv = { path = "../smpte-klv-rs" }
```

When updating the pinned revision, disable the local patch first. Refresh both lockfiles and verify them with `cargo test --locked` and `cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1`. Each lockfile must identify the Git source and revision.

## Guidelines

- **Tests.** Fixes come with a test that fails without the fix. Synthetic packets are built with the helpers in `tests/common/mod.rs`, or taken from the examples in the published MISB standards; prefer those over binary files, and never commit captured metadata.
- **No I/O, no mutation.** The library never reads files or sockets and never changes the input. Keep it that way.
- **Bounded memory.** Anything that buffers data or recurses into nested sets must have a limit in `Config` or a fixed cap. Hostile input must not be able to grow memory or recursion depth without bound.
- **Hot path.** Run the throughput example before and after changes to the decoder and include the numbers in the pull request.
- **C ABI.** Within a `MISB_ABI_VERSION`, only add: new functions, new constants, and new fields at the end of structs. Never change or remove existing ones, and never reuse a standard or value kind code. Update `include/misb.h` alongside `src/capi.rs`; the tests check that the two agree.
- **Generic KLV belongs in smpte-klv.** Keys, lengths, tags, set and pack framing and stream resynchronisation come from the [`smpte-klv`](https://github.com/notley-technologies/smpte-klv-rs) crate. Fix or extend SMPTE ST 336 behaviour there; this crate holds what MISB defines, such as tag tables, value mappings and the ST 0601 checksum.
- **Scope.** The crate decodes MISB ST 0601 and the sets and value encodings ST 0601 embeds. Other standards are welcome where ST 0601 carries them (for example the sets of tags 95, 97, 98 and 99, which are kept as bytes today); decoding other top-level keys is out of scope.
- **Standards.** When decoding a new standard or tag, cite the document and section or tag number in a comment, and keep `Standard::revision` and the README's table of revisions current.
- **Style.** Match the surrounding code. Comments explain why, not what. Use hyphens, not em dashes.

## Pull requests

Keep pull requests focused on one change and describe what it does and why. Add an entry under "Unreleased" in [CHANGELOG.md](CHANGELOG.md) for anything user-visible.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), as described in section 5 of the license.
