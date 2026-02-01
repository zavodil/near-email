# NEAR Email Integration Guide

Blockchain-native email for NEAR accounts. Every NEAR account automatically has an email address: `alice.near` → `alice@near.email`

## Use Cases

- **NFT Marketplace**: Notify users when their NFT is sold
- **DeFi Protocol**: Alert users about liquidation risk or completed transactions
- **DAO Governance**: Send voting reminders and proposal notifications
- **AI Agents**: Enable agents to communicate via email using their NEAR identity

## Architecture Overview

```
Your Contract/Agent
        │
        │ call request_execution()
        ▼
┌─────────────────────────────────────────┐
│        OutLayer Contract                │
│        (outlayer.near)                  │
└─────────────────────────────────────────┘
        │
        │ TEE execution
        ▼
┌─────────────────────────────────────────┐
│        NEAR Email WASI Module           │
│  - Derives user keys from master        │
│  - Encrypts/decrypts emails             │
│  - Sends via SMTP                       │
└─────────────────────────────────────────┘
        │
        ▼
    Email Delivered
```

---

## 1. Smart Contract Integration (Rust)

Smart contracts send emails by calling OutLayer's `request_execution` method, which triggers the NEAR Email WASI module.

### Dependencies

Add to your `Cargo.toml`:

```toml
[dependencies]
near-sdk = "5.9.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

### Cross-Contract Interface

```rust
use near_sdk::json_types::U128;
use near_sdk::{ext_contract, AccountId, Gas, NearToken, Promise};
use serde::Serialize;

/// Execution source for OutLayer
#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
pub enum ExecutionSource {
    Project {
        project_id: String,
        version_key: Option<String>,
    },
}

#[ext_contract(ext_outlayer)]
pub trait OutLayer {
    fn request_execution(
        &mut self,
        source: ExecutionSource,
        resource_limits: Option<serde_json::Value>,
        input_data: Option<String>,
        secrets_ref: Option<serde_json::Value>,
        response_format: Option<String>,
        payer_account_id: Option<AccountId>,
        params: Option<serde_json::Value>,
    );
}
```

### Example: NFT Sale Notification

```rust
use near_sdk::{env, near, near_bindgen, AccountId, Gas, NearToken, Promise};
use near_sdk::json_types::U128;
use serde_json::json;

// OutLayer contract (mainnet only - testnet not supported)
const OUTLAYER_CONTRACT: &str = "outlayer.near";
// Note: project_id is "zavodil.near/near-email" for external calls

#[near_bindgen]
impl NftMarketplace {
    /// Called when NFT is sold - sends email notification to seller
    ///
    /// ⚠️ WARNING: Email content is PUBLIC on the NEAR blockchain.
    /// Only use for automated notifications, never for private data.
    pub fn on_nft_sold(
        &mut self,
        seller_id: AccountId,
        token_id: String,
        price: U128,
    ) -> Promise {
        // Use send_email_plaintext for contract-initiated notifications
        // No ephemeral_pubkey needed - contract doesn't need the response
        let email_input = json!({
            "action": "send_email_plaintext",
            "to": format!("{}@near.email", seller_id),
            "subject": format!("Your NFT #{} was sold!", token_id),
            "body": format!(
                "Your NFT #{} sold for {} NEAR.\n\n\
                View transaction: https://nearblocks.io/txns/{}",
                token_id,
                price.0 as f64 / 1e24,
                env::block_timestamp()
            )
        });

        // Call OutLayer to execute NEAR Email WASI module
        ext_outlayer::ext(OUTLAYER_CONTRACT.parse().unwrap())
            .with_static_gas(Gas::from_tgas(100))
            .with_attached_deposit(NearToken::from_millinear(25))
            .request_execution(
                ExecutionSource::Project {
                    project_id: "zavodil.near/near-email".to_string(),
                    version_key: None,
                },
                None,                            // resource_limits
                Some(email_input.to_string()),   // input_data
                None,                            // secrets_ref
                Some("Json".to_string()),        // response_format
                None,                            // payer_account_id
                None,                            // params
            )
    }
}
```

### Example: DeFi Liquidation Alert

```rust
#[near_bindgen]
impl LendingProtocol {
    /// Alert user about liquidation risk
    ///
    /// ⚠️ WARNING: Email content is PUBLIC on the NEAR blockchain.
    pub fn send_liquidation_warning(
        &mut self,
        user_id: AccountId,
        health_factor: f64,
        collateral_value: U128,
    ) -> Promise {
        // Use send_email_plaintext - no ephemeral_pubkey needed for contracts
        let email_input = json!({
            "action": "send_email_plaintext",
            "to": format!("{}@near.email", user_id),
            "subject": "Liquidation Warning - Action Required",
            "body": format!(
                "Your position is at risk of liquidation.\n\n\
                Health Factor: {:.2}\n\
                Collateral Value: ${:.2}\n\n\
                Please add more collateral or repay part of your loan.\n\n\
                - Lending Protocol",
                health_factor,
                collateral_value.0 as f64 / 1e6
            )
        });

        ext_outlayer::ext(OUTLAYER_CONTRACT.parse().unwrap())
            .with_static_gas(Gas::from_tgas(100))
            .with_attached_deposit(NearToken::from_millinear(25))
            .request_execution(
                ExecutionSource::Project {
                    project_id: "zavodil.near/near-email".to_string(),
                    version_key: None,
                },
                None,                            // resource_limits
                Some(email_input.to_string()),   // input_data
                None,                            // secrets_ref
                Some("Json".to_string()),        // response_format
                None,                            // payer_account_id
                None,                            // params
            )
    }
}
```

---

## 2. AI Agent Integration

AI agents can integrate via two methods:

| Method | Best For | Payment |
|--------|----------|---------|
| **Payment Key (HTTPS)** | Server-side agents, high volume | Pre-paid balance (USDC/USDT) |
| **NEAR Transaction** | Browser wallets, direct signing | Deposit (unused portion refunded) |

---

### Option A: Payment Key (Subscription/Pre-paid)

Pre-fund a payment key and make simple HTTPS calls. Best for server-side agents.

**Setup:**
1. Go to [OutLayer Dashboard](https://outlayer.fastnear.com/dashboard)
2. Create a Payment Key
3. Top up balance with USDC/USDT
4. Copy key (format: `owner:nonce:secret`)

**JavaScript Example:**

```typescript
const OUTLAYER_API = 'https://api.outlayer.fastnear.com';
const PROJECT_ID = 'zavodil.near/near-email';
const PAYMENT_KEY = 'your-account.near:nonce:secret'; // From dashboard

// Send email via OutLayer API (plaintext - simplest option for agents)
async function sendEmail(to: string, subject: string, body: string): Promise<any> {
  const response = await fetch(`${OUTLAYER_API}/call/outlayer.near/${PROJECT_ID}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Payment-Key': PAYMENT_KEY,
    },
    body: JSON.stringify({
      input: {
        action: 'send_email_plaintext',
        to,
        subject,
        body,
      },
    }),
  });

  return response.json();
}

// Get email counts (no encryption needed)
async function getEmailCount(): Promise<any> {
  const response = await fetch(`${OUTLAYER_API}/call/outlayer.near/${PROJECT_ID}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Payment-Key': PAYMENT_KEY,
    },
    body: JSON.stringify({
      input: { action: 'get_email_count' },
    }),
  });

  return response.json();
}

// Usage
const result = await sendEmail('recipient@gmail.com', 'Hello from AI Agent', 'Test email.');
console.log('Email sent:', result);

const counts = await getEmailCount();
console.log(`Inbox: ${counts.output.inbox_count}, Sent: ${counts.output.sent_count}`);
```

For encrypted email flow (reading emails), see the Python example below which includes full ECDH encryption.

### Python Example

```python
import os
import requests

OUTLAYER_API = "https://api.outlayer.fastnear.com"
PROJECT_ID = "zavodil.near/near-email"
PAYMENT_KEY = os.environ.get("OUTLAYER_PAYMENT_KEY", "your-account.near:nonce:secret")


def send_email_plaintext(to: str, subject: str, body: str) -> dict:
    """Send email via OutLayer HTTPS API (plaintext - simplest option)"""

    payload = {
        "input": {
            "action": "send_email_plaintext",
            "to": to,
            "subject": subject,
            "body": body,
        },
    }

    response = requests.post(
        f"{OUTLAYER_API}/call/outlayer.near/{PROJECT_ID}",
        headers={
            "Content-Type": "application/json",
            "X-Payment-Key": PAYMENT_KEY,
        },
        json=payload,
    )

    response.raise_for_status()
    return response.json()


def get_email_count() -> dict:
    """Get inbox and sent email counts (no encryption needed)"""

    payload = {
        "input": {
            "action": "get_email_count",
        },
    }

    response = requests.post(
        f"{OUTLAYER_API}/call/outlayer.near/{PROJECT_ID}",
        headers={
            "Content-Type": "application/json",
            "X-Payment-Key": PAYMENT_KEY,
        },
        json=payload,
    )

    response.raise_for_status()
    return response.json()


# Usage example
if __name__ == "__main__":
    # Check email count
    count = get_email_count()
    print(f"Inbox: {count['output']['inbox_count']}, Sent: {count['output']['sent_count']}")

    # Send an email
    result = send_email_plaintext(
        to="recipient@example.com",
        subject="Hello from Python AI Agent",
        body="This email was sent by an AI agent using NEAR Email."
    )
    print(f"Email sent: {result}")
```

### Required Python Dependencies

```
pip install requests
```

### Advanced: Reading Emails (with Encryption)

For reading emails, you need ECDH encryption. See the [examples.md](../../skills/near-email-skill/examples.md) in the skill folder for full encrypted flow implementation.

---

### Option B: NEAR Transaction (Per-Use)

Sign transactions directly with NEAR wallet. Attach deposit as a limit for computation costs - unused portion is automatically refunded. This is how [near.email](https://near.email) works.

**CRITICAL: NEAR Transaction results are in the `outlayer.near` receipt's `SuccessValue` (base64-encoded JSON). Find the receipt where `executor_id === 'outlayer.near'`. The result is `{ "success": true, ... }` - NO `output` wrapper. Use `parseTransactionResult()` to extract it.**

**JavaScript Example (with near-api-js):**

```typescript
import { connect, keyStores, Contract } from 'near-api-js';

const OUTLAYER_CONTRACT = 'outlayer.near';
const PROJECT_ID = 'zavodil.near/near-email';

// Required resource limits for NEAR Email
const RESOURCE_LIMITS = {
  max_memory_mb: 512,
  max_instructions: 2000000000,
  max_execution_seconds: 120,
};

// Connect to NEAR
const near = await connect({
  networkId: 'mainnet',
  keyStore: new keyStores.BrowserLocalStorageKeyStore(),
  nodeUrl: 'https://rpc.mainnet.near.org',
});

const account = await near.account('your-account.near');

// REQUIRED: Parse output from outlayer.near receipt's SuccessValue
// Returns JSON directly: { success: true, ... } - NO "output" wrapper!
function parseTransactionResult(result: any): any {
  // Find receipt from outlayer.near contract (contains the execution result)
  const outlayerReceipt = result.receipts_outcome.find(
    (r: any) => r.outcome.executor_id === 'outlayer.near' && r.outcome.status.SuccessValue
  );
  if (!outlayerReceipt) {
    throw new Error('No SuccessValue from outlayer.near');
  }
  const decoded = Buffer.from(outlayerReceipt.outcome.status.SuccessValue, 'base64').toString();
  return JSON.parse(decoded); // { success: true, ... } - directly, no wrapper
}

// Send email via NEAR transaction
async function sendEmail(to: string, subject: string, body: string) {
  const input = JSON.stringify({
    action: 'send_email_plaintext',
    to,
    subject,
    body,
  });

  const result = await account.functionCall({
    contractId: OUTLAYER_CONTRACT,
    methodName: 'request_execution',
    args: {
      source: { Project: { project_id: PROJECT_ID, version_key: null } },
      input_data: input,
      resource_limits: RESOURCE_LIMITS,
      response_format: 'Json',
    },
    gas: BigInt('100000000000000'), // 100 TGas
    attachedDeposit: BigInt('25000000000000000000000'), // deposit, unused refunded
  });

  return parseTransactionResult(result);
}

// Usage
const output = await sendEmail('recipient@gmail.com', 'Hello', 'Sent via NEAR transaction!');
console.log('Email sent:', output); // { success: true, message_id: "..." }
```

**Python Example (with py-near):**

```python
from py_near.account import Account
import asyncio
import json
import re

OUTLAYER_CONTRACT = "outlayer.near"
PROJECT_ID = "zavodil.near/near-email"

# Required resource limits for NEAR Email
RESOURCE_LIMITS = {
    "max_memory_mb": 512,
    "max_instructions": 2000000000,
    "max_execution_seconds": 120,
}


def parse_transaction_result(result) -> dict:
    """Parse output from outlayer.near receipt's SuccessValue (base64 JSON).
    Returns: { success: True, ... } - directly, NO 'output' wrapper!
    """
    import base64
    # Find receipt from outlayer.near contract (contains the execution result)
    outlayer_receipt = next(
        (r for r in result.receipts_outcome
         if r.outcome.executor_id == "outlayer.near" and r.outcome.status.get("SuccessValue")),
        None
    )
    if not outlayer_receipt:
        raise ValueError("No SuccessValue from outlayer.near")
    success_value = outlayer_receipt.outcome.status.get("SuccessValue")
    decoded = base64.b64decode(success_value).decode()
    return json.loads(decoded)  # { success: True, ... } - directly


async def send_email(account: Account, to: str, subject: str, body: str):
    input_data = json.dumps({
        "action": "send_email_plaintext",
        "to": to,
        "subject": subject,
        "body": body,
    })

    result = await account.function_call(
        OUTLAYER_CONTRACT,
        "request_execution",
        {
            "source": {"Project": {"project_id": PROJECT_ID, "version_key": None}},
            "input_data": input_data,
            "resource_limits": RESOURCE_LIMITS,
            "response_format": "Json",
        },
        gas=100_000_000_000_000,  # 100 TGas
        deposit=25_000_000_000_000_000_000_000,  # deposit, unused refunded
    )

    return parse_transaction_result(result)

# Usage
account = Account("your-account.near", private_key="ed25519:...")
output = asyncio.run(send_email(account, "recipient@gmail.com", "Hello", "Sent via NEAR!"))
print(f"Email sent: {output}")  # { success: True, message_id: "..." }
```

---

## 3. API Reference

### Actions

| Action | Description |
|--------|-------------|
| `get_emails` | Fetch inbox and sent emails (encrypted response) |
| `send_email` | Send an email (encrypted payload) |
| `send_email_plaintext` | Send email with plaintext content (for smart contracts) |
| `delete_email` | Delete an email by ID |
| `get_email_count` | Get inbox/sent counts (no encryption) |
| `get_send_pubkey` | Get sender's pubkey for encrypting emails (no encryption) |
| `get_attachment` | Fetch a large attachment by ID |
| `get_master_public_key` | Get the master public key for encryption |

### Request Format

All requests use the same structure:

```json
{
  "input": {
    "action": "action_name",
    // action-specific parameters
  }
}
```

### GetEmails Request

```json
{
  "action": "get_emails",
  "ephemeral_pubkey": "02abc123...",
  "inbox_offset": 0,
  "sent_offset": 0,
  "max_output_size": 1500000
}
```

### SendEmail Request

```json
{
  "action": "send_email",
  "encrypted_data": "base64-ecies-ciphertext",
  "ephemeral_pubkey": "02abc123..."
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `encrypted_data` | Yes | ECIES ciphertext with `to`, `subject`, `body`, `attachments` (encrypt with your `send_pubkey`) |
| `ephemeral_pubkey` | No | For response encryption. If omitted, returns simple status without inbox/sent. |

Response with `ephemeral_pubkey`: `{ "success": true, "message_id": "...", "encrypted_data": "..." }`
Response without: `{ "success": true, "message_id": "..." }`

### SendEmailPlaintext Request (for Smart Contracts)

⚠️ **WARNING**: Email content is stored PUBLICLY on the NEAR blockchain.
Use only for automated notifications (NFT sales, DeFi alerts, DAO votes).

```json
{
  "action": "send_email_plaintext",
  "to": "recipient@near.email",
  "subject": "Your NFT was sold!",
  "body": "NFT #123 sold for 10 NEAR."
}
```

Optional: `attachments` array (same format as send_email).

Response: `{ "success": true, "message_id": "..." }`

### DeleteEmail Request

```json
{
  "action": "delete_email",
  "email_id": "uuid-of-email",
  "ephemeral_pubkey": "02abc123..."
}
```

---

## 4. Encryption Details

NEAR Email uses ECDH + ChaCha20-Poly1305 for end-to-end encryption.

### EC01 Format

```
EC01 (4 bytes magic) ||
ephemeral_pubkey (33 bytes, compressed secp256k1) ||
nonce (12 bytes) ||
ciphertext + auth_tag (variable + 16 bytes)
```

### Key Derivation

User keys are derived from a master key stored in TEE:

```
user_pubkey = master_pubkey + SHA256("near-email:v1:" + account_id) * G
user_privkey = master_privkey + SHA256("near-email:v1:" + account_id)
```

This allows anyone to compute a user's public key for encryption, but only the TEE can derive private keys for decryption.

---

## 5. Limits

| Parameter | Transaction Mode | Payment Key Mode |
|-----------|-----------------|------------------|
| Max response size | 1.5 MB | 25 MB |
| Max file per attachment | 5 MB | 5 MB |
| Max total email size | 7 MB | 7 MB |
| Max attachments per email | 10 | 10 |

---

## 6. Network

NEAR Email currently supports **mainnet only**. Emails to `*.testnet` accounts are not processed.

| Network | OutLayer Contract | API Base |
|---------|-------------------|----------|
| Mainnet | `outlayer.near` | `https://api.outlayer.fastnear.com` |

---

## Resources

- [NEAR Email Web UI](https://near.email)
- [OutLayer Dashboard](https://outlayer.fastnear.com/dashboard)
- [OutLayer Documentation](https://outlayer.fastnear.com/docs)
