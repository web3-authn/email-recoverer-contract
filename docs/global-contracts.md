# Global Contracts Rollout Plan for Email Recoverer

This document describes how to migrate the `email-recoverer` contract to use **Global Contracts** (NEP‑0591) so that:

- The contract code is stored once globally instead of per user.
- Each user account (`<user>.near`) still has its **own state** and can be initialized independently.
- Browser‑based clients (no CLI access) can continue to deploy/initialize their per‑account instances.

The plan is intentionally incremental so we can adopt global contracts without breaking existing flows.

---

## 1. Goals and Non‑Goals

**Goals**

- Reduce per‑user storage cost when enabling email recovery.
- Keep the “per‑account recoverer” model: state lives on `<user>.near`.
- Support browser‑only clients that sign transactions via JS SDKs (no `near` CLI).
- Preserve the ability to upgrade the recoverer implementation in the early phases.

**Non‑Goals (for now)**

- We will not immediately migrate all existing per‑user contracts.
- We will not expose a UI for users to choose between “by account ID” vs “by hash” global contracts; this remains an infra decision.

> Note: for this rollout we assume a completely new deployment of `email-recoverer` with no legacy contracts or migration steps required.

---

## 2. High‑Level Design

Today:

- We build `email-recoverer` WASM.
- We deploy it as a regular contract to some “code host” account like `email-recoverer.$CONTRACT_ID`.
- For each user that enables recovery, we deploy the same WASM to `<user>.near` and call `new(...)`.

With **Global Contracts**:

1. We deploy `email-recoverer` **once as a global contract** (either **by account ID** or **by hash**).
2. For each user, we:
   - Attach the global contract code to `<user>.near` using `UseGlobalContractAction` (`useGlobalContract` in SDKs).
   - Call `new(...)` on `<user>.near` with the usual initialization args.

This yields:

- One‑time higher cost to publish the global contract (burned storage).
- Very cheap per‑user deployments (only a short identifier + state storage).

---

## 3. Choosing Global Contract Mode

NEP‑0591 supports two reference modes:

- **By Account ID** (upgradable):
  - Global contract is addressed by an account (e.g. `email-recoverer-code.your-app.testnet`).
  - Redeploying code on that account transparently upgrades all users that reference it.
  - Good for rapid iteration and security patches.

- **By Hash** (immutable):
  - Global contract is addressed by its code hash.
  - Each new version is a new hash; users only move when we explicitly switch them.
  - Better for strong immutability / audit guarantees.

**Plan**

- **Phase 1:** Use **Global Contract by Account ID** for `email-recoverer` while the feature is evolving.
- **Phase 2:** Once stable/audited, optionally pin a specific version as **Global Contract by Hash** for production users who want immutability.

---

## 4. Build & Global Deployment Pipeline

We already have reproducible builds wired via `cargo-near` in `email-recoverer/Cargo.toml`:

- `cargo near build reproducible-wasm --manifest-path email-recoverer/Cargo.toml --out-dir target/near-repro`

**Step 4.1 – Build**

- Use the existing reproducible build command to produce:
  - `target/near-repro/email_recoverer_factory.wasm`

**Step 4.2 – Deploy as Global Contract (by Account ID)**

Pick a dedicated global contract account, e.g.:

- `email-recoverer-code.<app-root>.testnet`

Then, from CI or an operator machine (not the browser):

```bash
near contract deploy-as-global \
  use-file target/near-repro/email_recoverer_factory.wasm \
  as-global-account-id email-recoverer-code.<app-root>.testnet \
  network-config <network> \
  sign-with-keychain \
  send
```

Notes:

- This burns NEAR for global storage (10× storage cost per byte), paid once.
- After distribution completes, any account can reference this code by account ID.

**Step 4.3 – Track Global Contract Identifier**

- Add a configuration variable (e.g. in `.env` / frontend config):
  - `GLOBAL_EMAIL_RECOVERER_ACCOUNT_ID=email-recoverer-code.<app-root>.testnet`
- Frontend and backend code will use this value when calling `useGlobalContract`.

---

## 5. Per‑User Deployment Flow (Browser / JS SDK)

Users currently sign and send a `deployContract` transaction from the browser.
With global contracts, they should instead:

1. **Attach the global contract** to their account via `UseGlobalContractAction`.
2. **Initialize** their recoverer by calling `new(...)`.

This is done via SDKs, *not* via the CLI.

### 5.1. JS SDK Shape (Account ID mode)

Using the `@near-js` style APIs (or similar) from the browser:

```ts
// 1) Attach global email-recoverer code to <user>.near
await userAccount.useGlobalContract({
  accountId: GLOBAL_EMAIL_RECOVERER_ACCOUNT_ID,
});

// 2) Initialize the per-account recoverer state on <user>.near
await userAccount.functionCall({
  contractId: userAccount.accountId, // e.g. "bob.near"
  methodName: "new",
  args: {
    zk_email_verifier: "zk-email-verifier.testnet",
    email_dkim_verifier: "email-dkim-verifier.testnet",
    policy: null,
    recovery_emails: [...], // hashed emails
  },
  gas,
  attachedDeposit, // typically 0 for init, unless we change API
});
```

Implementation details:

- The UI should send both actions either:
  - In a **single transaction with two actions** (use global + init), or
  - As two sequential transactions, handling errors at each step.
- If the account already has a contract, we must decide whether:
  - To require users to migrate manually, or
  - To treat this as “upgrade to global” and `useGlobalContract` over the existing code.

### 5.2. Hash Mode (Optional)

If we later publish an immutable version by hash, the browser flow would instead pass:

```ts
await userAccount.useGlobalContract({
  codeHash: <Uint8Array of 32 bytes>,
});
```

The hash can be distributed by the backend or config (e.g. bs58‑encoded string decoded client‑side).

---

## 6. Migration Strategy

We expect some users to already have per‑account deployments of `email-recoverer` using regular `deployContract`.

**Option A – “New Users Only” (simplest)**

- For existing accounts:
  - Leave their current deployment in place.
  - Only use the global‑contract flow for **newly onboarded** users.
- Pros: minimal complexity, no data migration.
- Cons: mixed population (some users pay more storage).

**Option B – Soft Migration on Next Upgrade**

For accounts where we already control an upgrade path (e.g., via your UI or a management key):

1. When the user next visits the recovery UI, detect:
   - `contract_code_hash` vs the global code hash / account.
2. If they are not already using the global contract:
   - Offer a one‑click “upgrade to global contract” flow:
     - Call `useGlobalContract` referencing the global contract.
     - Optionally re‑run `new` or a dedicated migration method if state layout changed (not currently the case).

This keeps the user’s **state** but switches them to shared code.

---

## 7. Testing and Rollout

**7.1. Local / Sandbox Testing**

- Use `near-workspaces` integration tests to simulate:
  - Deploying `email-recoverer` as a global contract (via RPC).
  - Creating a user account, calling `useGlobalContract`, then `new(...)`.
  - Invoking `set_recovery_emails`, `verify_and_recover`, `verify_dkim_and_recover` to ensure behavior matches non‑global deployments.

**7.2. Testnet Rollout**

1. Deploy the global contract on **testnet** using the pipeline in Section 4.
2. Point a staging/QA frontend at:
   - `GLOBAL_EMAIL_RECOVERER_ACCOUNT_ID` on testnet.
3. Run end‑to‑end recovery flows with a few test accounts.

**7.3. Mainnet Rollout**

1. Repeat the deployment pipeline targeting mainnet.
2. Gradually enable global‑contract deployment in the production frontend (e.g. feature flag / config).
3. Monitor:
   - User gas/storage usage for the recovery enablement flow.
   - Any errors related to `GlobalContractDoesNotExist` (premature use before distribution completes).

---

## 8. Future Enhancements

- **Support both by‑account and by‑hash references**:
  - Developers choose per environment (e.g. testnet = account ID; mainnet = hash).
- **Expose versioning in the UI**:
  - Show which global contract version a user’s account is running.
- **Centralize verifier references**:
  - Combine global deployment of verifier contracts (`zk-email-verifier`, DKIM verifier) with the global `email-recoverer` to further reduce redundant deployments.
