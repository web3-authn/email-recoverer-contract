
## `deploy.sh` vs `deploy-global.sh`

`deploy.sh` only deploys/initializes a normal contract on CONTRACT_ID (e.g. w3a-email-recoverer-v1.testnet); it does not touch the global contract code published via `deploy-as-global.sh`.

`deploy.sh` overwrites the code on the `w3a-email-recoverer-v1.testnet` account and calls `new()`.
- It affects what NearBlocks shows and what you get when you call methods directly on w3a-email-recoverer-v1.testnet.

The global contract created with `deploy-global.sh`:
- Lives in the NEP‑0591 global code store, **keyed by as-global-account-id "$CONTRACT_ID"**.
- It is only updated when you run `near contract deploy-as-global …` again (i.e., deploy-global.sh / upgrade-global.sh), not by normal cargo near deploy.


Running `deploy.sh` does not change the global contract; it only updates the regular contract code on the w3a-email-recoverer-v1.testnet account for NEAR blocks display purposes.