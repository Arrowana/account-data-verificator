# Account data verificator

Small Pinocchio program that verifies a SHA-256 digest over the suffix of account data starting at a given offset.

Use case:

- [redacted]

Instruction format:

- `u8` discriminator: `0`
- `u32` start offset, little endian
- `[u8; 32]` expected SHA-256 digest

Accounts:

- `[0]` readonly target account whose data suffix `account_data[start_offset..]` is verified

Current measured limit:

- the LiteSVM max-CU test currently finds a largest verified payload of `2,799,325` bytes at the Solana max transaction compute budget of `1,400,000` CU in this environment
- that matches the SHA-256 syscall cost model closely: `85` CU base plus roughly `1` CU per `2` hashed bytes implies a pure-hash ceiling of about `2,799,830` bytes, with the remaining gap coming from fixed instruction overhead
- the benchmark test uses `start_offset = 0`, so that number reflects hashing the entire account data from the beginning

Useful commands:

```bash
cargo build-sbf --features bpf-entrypoint
cargo test -- --nocapture
```
