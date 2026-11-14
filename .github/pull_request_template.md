## What and why

<!-- What this changes and the reason for it. Link the issue if there is one. -->

## Checklist

- [ ] Tests cover the change (a fix includes a test that fails without it)
- [ ] `cargo test --all-features` and `cargo test` (default features) pass
- [ ] No new warnings (`RUSTFLAGS="-D warnings" cargo build --all-targets --all-features`)
- [ ] New decoding rules cite the MISB standard and tag
- [ ] C ABI changes only add functions, constants or trailing struct fields, and `include/misb.h` is updated
- [ ] CHANGELOG.md, and README.md where it describes the change, updated for user-visible changes
- [ ] Throughput numbers included for changes to the decoder hot path
