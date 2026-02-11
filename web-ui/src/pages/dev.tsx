import Link from 'next/link';
import Head from 'next/head';
import { useState } from 'react';

// Code examples
const CODE_EXAMPLES = {
  // Rust smart contract examples
  rustDependencies: `[dependencies]
near-sdk = "5.9.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"`,

  rustInterface: `use near_sdk::json_types::U128;
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
}`,

  rustNftExample: `use near_sdk::{env, near, near_bindgen, AccountId, Gas, NearToken, Promise};
use serde_json::json;

const OUTLAYER_CONTRACT: &str = "outlayer.near";

#[near_bindgen]
impl NftMarketplace {
    /// Called when NFT is sold - sends email notification to seller
    ///
    /// WARNING: Email content is PUBLIC on the NEAR blockchain.
    /// Only use for automated notifications, never for private data.
    pub fn on_nft_sold(
        &mut self,
        seller_id: AccountId,
        token_id: String,
        price: U128,
    ) -> Promise {
        let email_input = json!({
            "action": "send_email_plaintext",
            "to": format!("{}@near.email", seller_id),
            "subject": format!("Your NFT #{} was sold!", token_id),
            "body": format!(
                "Your NFT #{} sold for {} NEAR.\\n\\n\\
                View transaction: https://nearblocks.io/txns/{}",
                token_id,
                price.0 as f64 / 1e24,
                env::block_timestamp()
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
                None,
                Some(email_input.to_string()),
                None,
                Some("Json".to_string()),
                None,
                None,
            )
    }
}`,

  // JavaScript Payment Key examples
  jsPaymentKey: `import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { chacha20poly1305 } from '@noble/ciphers/chacha';

const OUTLAYER_API = 'https://api.outlayer.fastnear.com';
const PROJECT_ID = 'zavodil.near/near-email';
const PAYMENT_KEY = 'your-account.near:nonce:secret'; // From dashboard

// Send email via OutLayer API (plaintext - simplest option)
async function sendEmail(to: string, subject: string, body: string) {
  const response = await fetch(
    \`\${OUTLAYER_API}/call/\${PROJECT_ID}\`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Payment-Key': PAYMENT_KEY,
      },
      body: JSON.stringify({
        input: { action: 'send_email_plaintext', to, subject, body },
      }),
    }
  );
  return response.json();
}

// Read emails (requires ECIES decryption)
async function getEmails() {
  // Generate ephemeral keypair for response decryption
  const ephemeralPrivkey = secp256k1.utils.randomPrivateKey();
  const ephemeralPubkey = secp256k1.getPublicKey(ephemeralPrivkey, true);
  const ephemeralPubkeyHex = Buffer.from(ephemeralPubkey).toString('hex');

  const response = await fetch(
    \`\${OUTLAYER_API}/call/\${PROJECT_ID}\`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Payment-Key': PAYMENT_KEY,
      },
      body: JSON.stringify({
        input: {
          action: 'get_emails',
          ephemeral_pubkey: ephemeralPubkeyHex,
          max_output_size: 1500000,
        },
      }),
    }
  );

  const result = await response.json();

  // Decrypt response (EC01 format: magic + sender_pubkey + nonce + ciphertext)
  const encrypted = Buffer.from(result.output.encrypted_data, 'base64');
  const senderPubkey = encrypted.slice(4, 37);
  const nonce = encrypted.slice(37, 49);
  const ciphertext = encrypted.slice(49);

  // ECDH key exchange
  const sharedPoint = secp256k1.getSharedSecret(ephemeralPrivkey, senderPubkey, true);
  const key = sha256(sharedPoint.slice(1));

  // Decrypt with ChaCha20-Poly1305
  const cipher = chacha20poly1305(key, nonce);
  const plaintext = cipher.decrypt(ciphertext);
  const emailData = JSON.parse(new TextDecoder().decode(plaintext));

  return {
    inbox: emailData.inbox,
    sent: emailData.sent,
    inboxCount: result.output.inbox_count,
    sentCount: result.output.sent_count,
  };
}

// Usage
await sendEmail('user@gmail.com', 'Hello', 'Test email');

const { inbox, inboxCount } = await getEmails();
console.log(\`You have \${inboxCount} emails\`);
inbox.forEach(email => console.log(\`From: \${email.from}\`));`,

  // JavaScript NEAR Transaction examples
  jsTransaction: `import { connect, keyStores } from 'near-api-js';

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
    (r: any) =>
      r.outcome.executor_id === 'outlayer.near' &&
      r.outcome.status.SuccessValue
  );
  if (!outlayerReceipt) {
    throw new Error('No SuccessValue from outlayer.near');
  }
  const decoded = Buffer.from(
    outlayerReceipt.outcome.status.SuccessValue,
    'base64'
  ).toString();
  return JSON.parse(decoded);
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
const output = await sendEmail('user@gmail.com', 'Hello', 'Sent via NEAR!');
console.log('Email sent:', output); // { success: true, message_id: "..." }`,

  // Python Payment Key examples
  pythonPaymentKey: `import os
import hashlib
import secrets
import base64
import json
import requests
from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

OUTLAYER_API = "https://api.outlayer.fastnear.com"
PROJECT_ID = "zavodil.near/near-email"
PAYMENT_KEY = os.environ.get("OUTLAYER_PAYMENT_KEY", "your-account.near:nonce:secret")


def send_email_plaintext(to: str, subject: str, body: str) -> dict:
    """Send email via OutLayer HTTPS API (plaintext - simplest option)"""
    response = requests.post(
        f"{OUTLAYER_API}/call/{PROJECT_ID}",
        headers={"Content-Type": "application/json", "X-Payment-Key": PAYMENT_KEY},
        json={"input": {"action": "send_email_plaintext", "to": to, "subject": subject, "body": body}},
    )
    response.raise_for_status()
    return response.json()


def get_emails() -> dict:
    """Read emails (requires ECIES decryption)"""
    # Generate ephemeral keypair for response decryption
    ephemeral_privkey = PrivateKey()
    ephemeral_pubkey_hex = ephemeral_privkey.public_key.format(compressed=True).hex()

    response = requests.post(
        f"{OUTLAYER_API}/call/{PROJECT_ID}",
        headers={"Content-Type": "application/json", "X-Payment-Key": PAYMENT_KEY},
        json={"input": {"action": "get_emails", "ephemeral_pubkey": ephemeral_pubkey_hex, "max_output_size": 1500000}},
    )
    response.raise_for_status()
    result = response.json()

    # Decrypt response (EC01 format: magic + sender_pubkey + nonce + ciphertext)
    encrypted = base64.b64decode(result["output"]["encrypted_data"])
    sender_pubkey = PublicKey(encrypted[4:37])
    nonce = encrypted[37:49]
    ciphertext = encrypted[49:]

    # ECDH key exchange
    shared_point = sender_pubkey.multiply(ephemeral_privkey.secret)
    shared_x = shared_point.format(compressed=True)[1:]
    key = hashlib.sha256(shared_x).digest()

    # Decrypt with ChaCha20-Poly1305
    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    email_data = json.loads(plaintext.decode())

    return {
        "inbox": email_data.get("inbox", []),
        "sent": email_data.get("sent", []),
        "inbox_count": result["output"].get("inbox_count", 0),
        "sent_count": result["output"].get("sent_count", 0),
    }


# Usage
if __name__ == "__main__":
    send_email_plaintext("user@example.com", "Hello from Python", "Sent by AI agent")

    emails = get_emails()
    print(f"Inbox: {emails['inbox_count']} emails")
    for email in emails["inbox"]:
        print(f"  From: {email['from']}, Subject: {email['subject']}")`,

  // Python NEAR Transaction examples
  pythonTransaction: `from py_near.account import Account
import asyncio
import json
import base64

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
    # Find receipt from outlayer.near contract (contains the execution result)
    outlayer_receipt = next(
        (r for r in result.receipts_outcome
         if r.outcome.executor_id == "outlayer.near"
         and r.outcome.status.get("SuccessValue")),
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
output = asyncio.run(send_email(account, "user@gmail.com", "Hello", "Sent via NEAR!"))
print(f"Email sent: {output}")  # { success: True, message_id: "..." }`,
};

// Collapsible code block component
function CodeBlock({
  title,
  code,
  language = 'typescript',
  defaultOpen = false
}: {
  title: string;
  code: string;
  language?: string;
  defaultOpen?: boolean;
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const [copied, setCopied] = useState(false);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="border border-gray-200 rounded-xl overflow-hidden mb-4">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-4 py-3 bg-gray-50 flex items-center justify-between hover:bg-gray-100 transition-colors"
      >
        <div className="flex items-center gap-2">
          <svg
            className={`w-4 h-4 text-gray-500 transition-transform ${isOpen ? 'rotate-90' : ''}`}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          <span className="font-medium text-gray-700">{title}</span>
        </div>
        <span className="text-xs text-gray-400 uppercase">{language}</span>
      </button>

      {isOpen && (
        <div className="relative">
          <button
            onClick={copyToClipboard}
            className="absolute top-2 right-2 px-3 py-1.5 bg-white/90 hover:bg-white border border-gray-200 rounded-lg text-xs font-medium text-gray-600 hover:text-gray-900 transition-colors flex items-center gap-1.5 z-10"
          >
            {copied ? (
              <>
                <svg className="w-3.5 h-3.5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                Copied!
              </>
            ) : (
              <>
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
                Copy
              </>
            )}
          </button>
          <pre className="p-4 bg-gray-900 text-gray-100 text-sm overflow-x-auto">
            <code>{code}</code>
          </pre>
        </div>
      )}
    </div>
  );
}

export default function DevPage() {
  return (
    <>
      <Head>
        <title>Developer Integration | near.email</title>
        <meta name="description" content="Integrate NEAR Email into your smart contracts, AI agents, and applications" />
      </Head>

      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
        {/* Header */}
        <header className="bg-white/80 backdrop-blur-sm border-b border-gray-100 px-4 py-3 sticky top-0 z-40">
          <div className="max-w-4xl mx-auto flex items-center justify-between">
            <Link href="/" className="text-lg font-semibold text-gray-900 hover:text-blue-600 transition-colors">
              near.email
            </Link>
            <div className="flex items-center gap-4">
              <Link href="/docs" className="text-sm text-gray-500 hover:text-gray-700 transition-colors">
                How it works
              </Link>
              <Link href="/" className="text-sm text-gray-500 hover:text-gray-700 transition-colors">
                Back to app
              </Link>
            </div>
          </div>
        </header>

        {/* Content */}
        <main className="max-w-4xl mx-auto px-4 py-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Developer Integration
          </h1>
          <p className="text-lg text-gray-500 mb-8">
            Send blockchain-native emails from smart contracts, AI agents, and applications
          </p>

          {/* Quick Reference */}
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-5 mb-8">
            <h2 className="text-lg font-semibold text-blue-900 mb-3">Quick Reference</h2>
            <div className="grid md:grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-blue-600 font-medium">Contract:</span>
                <code className="ml-2 bg-blue-100 px-2 py-0.5 rounded text-blue-800">outlayer.near</code>
              </div>
              <div>
                <span className="text-blue-600 font-medium">Project ID:</span>
                <code className="ml-2 bg-blue-100 px-2 py-0.5 rounded text-blue-800">zavodil.near/near-email</code>
              </div>
              <div>
                <span className="text-blue-600 font-medium">API Base:</span>
                <code className="ml-2 bg-blue-100 px-2 py-0.5 rounded text-blue-800">api.outlayer.fastnear.com</code>
              </div>
              <div>
                <span className="text-blue-600 font-medium">Address space:</span>
                <span className="ml-2 text-blue-800"><code className="bg-blue-100 px-1.5 py-0.5 rounded">alice.near</code> = <code className="bg-blue-100 px-1.5 py-0.5 rounded">alice@near.email</code></span>
              </div>
            </div>            
          </div>

          {/* Use Cases */}
          <h2 className="text-xl font-bold text-gray-900 mb-2">
            Use Cases
          </h2>
          <div className="grid md:grid-cols-2 gap-4 mb-10">
            <div className="bg-white rounded-xl border border-gray-200 p-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-8 h-8 bg-purple-100 rounded-lg flex items-center justify-center">
                  <svg className="w-4 h-4 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                  </svg>
                </div>
                <h3 className="font-semibold text-gray-900">NFT Marketplace</h3>
              </div>
              <p className="text-gray-600 text-sm">Notify users when their NFT is sold</p>
            </div>
            <div className="bg-white rounded-xl border border-gray-200 p-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center">
                  <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h3 className="font-semibold text-gray-900">DeFi Protocol</h3>
              </div>
              <p className="text-gray-600 text-sm">Alert users about liquidation risk</p>
            </div>
            <div className="bg-white rounded-xl border border-gray-200 p-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-8 h-8 bg-orange-100 rounded-lg flex items-center justify-center">
                  <svg className="w-4 h-4 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                </div>
                <h3 className="font-semibold text-gray-900">DAO Governance</h3>
              </div>
              <p className="text-gray-600 text-sm">Send voting reminders and proposal notifications</p>
            </div>
            <div className="bg-white rounded-xl border border-gray-200 p-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                  <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                </div>
                <h3 className="font-semibold text-gray-900">AI Agents</h3>
              </div>
              <p className="text-gray-600 text-sm">Enable agents to communicate via email</p>
            </div>
          </div>

          {/* Integration Methods */}
          <div className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Integration Methods</h2>
            <div className="overflow-x-auto mb-6">
              <table className="w-full text-sm border border-gray-200 rounded-xl overflow-hidden">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="text-left py-3 px-4 font-medium text-gray-600">Method</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-600">Best For</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-600">Payment</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  <tr>
                    <td className="py-3 px-4 font-medium text-gray-900">Smart Contract (Rust)</td>
                    <td className="py-3 px-4 text-gray-600">On-chain notifications</td>
                    <td className="py-3 px-4 text-gray-600">Deposit (unused refunded)</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 font-medium text-gray-900">Payment Key (HTTPS)</td>
                    <td className="py-3 px-4 text-gray-600">Server-side agents, high volume</td>
                    <td className="py-3 px-4 text-gray-600">Pre-paid balance (USDC)</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 font-medium text-gray-900">NEAR Transaction</td>
                    <td className="py-3 px-4 text-gray-600">Browser wallets, direct signing</td>
                    <td className="py-3 px-4 text-gray-600">Deposit (unused refunded)</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Section 1: Smart Contract Integration */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-2">1. Smart Contract Integration (Rust)</h2>
            <p className="text-gray-600 mb-4">
              Smart contracts send emails by calling OutLayer&apos;s <code className="bg-gray-100 px-1.5 py-0.5 rounded text-sm">request_execution</code> method.
            </p>

            <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 mb-4">
              <div className="flex items-start gap-2">
                <svg className="w-5 h-5 text-amber-600 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <div>
                  <span className="font-semibold text-amber-800">Warning:</span>
                  <span className="text-amber-700 ml-1">
                    Email content (to, subject, body) is stored <strong>publicly</strong> on the NEAR blockchain.
                    Use <code className="bg-amber-100 px-1 rounded">send_email_plaintext</code> only for automated notifications.
                  </span>
                </div>
              </div>
            </div>

            <CodeBlock title="Cargo.toml Dependencies" code={CODE_EXAMPLES.rustDependencies} language="toml" />
            <CodeBlock title="Cross-Contract Interface" code={CODE_EXAMPLES.rustInterface} language="rust" />
            <CodeBlock title="Example: NFT Sale Notification" code={CODE_EXAMPLES.rustNftExample} language="rust" />
          </section>

          {/* Section 2: Payment Key (HTTPS API) */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-2">2. Payment Key (HTTPS API)</h2>
            <p className="text-gray-600 mb-4">
              Pre-fund a payment key and make simple HTTPS calls. Best for server-side agents.
            </p>

            <div className="bg-white rounded-xl border border-gray-200 p-5 mb-4">
              <h3 className="font-semibold text-gray-900 mb-3">Setup Steps</h3>
              <ol className="space-y-2 text-gray-700 text-sm">
                <li className="flex gap-3">
                  <span className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 font-medium flex-shrink-0">1</span>
                  <span>
                    Go to{' '}
                    <a href="https://outlayer.fastnear.com/payment-keys" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                      OutLayer Dashboard &rarr; Payment Keys
                    </a>
                  </span>
                </li>
                <li className="flex gap-3">
                  <span className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 font-medium flex-shrink-0">2</span>
                  <span>Create a new key and add USD balance</span>
                </li>
                <li className="flex gap-3">
                  <span className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 font-medium flex-shrink-0">3</span>
                  <span>Copy the key (format: <code className="bg-gray-100 px-1 rounded">owner:nonce:secret</code>)</span>
                </li>
              </ol>
            </div>

            <div className="bg-green-50 border border-green-200 rounded-xl p-4 mb-4">
              <div className="flex items-start gap-2">
                <svg className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <div>
                  <span className="font-semibold text-green-800">Privacy:</span>
                  <span className="text-green-700 ml-1">
                    Use <code className="bg-green-100 px-1 rounded">send_email</code> with ECIES encryption for private emails &mdash; only the recipient can decrypt.
                    Examples below use <code className="bg-green-100 px-1 rounded">send_email_plaintext</code> for simplicity (content is public on-chain).
                  </span>
                </div>
              </div>
            </div>

            <CodeBlock title="JavaScript / TypeScript" code={CODE_EXAMPLES.jsPaymentKey} language="typescript" />
            <CodeBlock title="Python" code={CODE_EXAMPLES.pythonPaymentKey} language="python" />
          </section>

          {/* Section 3: NEAR Transaction */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-2">3. NEAR Transaction (Per-Use)</h2>
            <p className="text-gray-600 mb-4">
              Sign transactions directly with NEAR wallet. Attach deposit as a limit for computation costs &mdash; unused portion is automatically refunded.
            </p>

            <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-4">
              <div className="flex items-start gap-2">
                <svg className="w-5 h-5 text-red-600 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                <div>
                  <span className="font-semibold text-red-800">Critical:</span>
                  <span className="text-red-700 ml-1">
                    NEAR Transaction results are in the <code className="bg-red-100 px-1 rounded">outlayer.near</code> receipt&apos;s <code className="bg-red-100 px-1 rounded">SuccessValue</code> (base64-encoded JSON).
                    Find the receipt where <code className="bg-red-100 px-1 rounded">executor_id === &apos;outlayer.near&apos;</code>.
                    Returns <code className="bg-red-100 px-1 rounded">{`{ "success": true, ... }`}</code> directly &mdash; <strong>NO <code>output</code> wrapper!</strong>
                  </span>
                </div>
              </div>
            </div>

            <div className="bg-green-50 border border-green-200 rounded-xl p-4 mb-4">
              <div className="flex items-start gap-2">
                <svg className="w-5 h-5 text-green-600 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <div>
                  <span className="font-semibold text-green-800">Privacy:</span>
                  <span className="text-green-700 ml-1">
                    Use <code className="bg-green-100 px-1 rounded">send_email</code> with ECIES encryption for private emails &mdash; only the recipient can decrypt.
                    Examples below use <code className="bg-green-100 px-1 rounded">send_email_plaintext</code> for simplicity (content is public on-chain).
                  </span>
                </div>
              </div>
            </div>

            <CodeBlock title="JavaScript / TypeScript (near-api-js)" code={CODE_EXAMPLES.jsTransaction} language="typescript" />
            <CodeBlock title="Python (py-near)" code={CODE_EXAMPLES.pythonTransaction} language="python" />
          </section>

          {/* API Actions */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">API Actions</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm border border-gray-200 rounded-xl overflow-hidden">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="text-left py-3 px-4 font-medium text-gray-600">Action</th>
                    <th className="text-left py-3 px-4 font-medium text-gray-600">Description</th>
                    <th className="text-center py-3 px-4 font-medium text-gray-600">Encryption</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  <tr>
                    <td className="py-3 px-4 font-mono text-blue-600">send_email_plaintext</td>
                    <td className="py-3 px-4 text-gray-600">Send email <span className="text-red-500 text-xs">(PUBLIC on-chain)</span></td>
                    <td className="text-center py-3 px-4 text-red-400">None</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 font-mono text-blue-600">send_email</td>
                    <td className="py-3 px-4 text-gray-600">Send email <span className="text-green-600 text-xs">(private, only recipient decrypts)</span></td>
                    <td className="text-center py-3 px-4 text-green-600">ECIES</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 font-mono text-blue-600">get_emails</td>
                    <td className="py-3 px-4 text-gray-600">Fetch inbox and sent emails</td>
                    <td className="text-center py-3 px-4 text-green-600">ECIES</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 font-mono text-blue-600">delete_email</td>
                    <td className="py-3 px-4 text-gray-600">Delete email by ID</td>
                    <td className="text-center py-3 px-4 text-green-600">ECIES</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 font-mono text-blue-600">get_email_count</td>
                    <td className="py-3 px-4 text-gray-600">Get inbox/sent counts</td>
                    <td className="text-center py-3 px-4 text-gray-400">None</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 font-mono text-blue-600">get_send_pubkey</td>
                    <td className="py-3 px-4 text-gray-600">Get sender&apos;s pubkey for encryption</td>
                    <td className="text-center py-3 px-4 text-gray-400">None</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* Limits */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Limits</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm border border-gray-200 rounded-xl overflow-hidden">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="text-left py-3 px-4 font-medium text-gray-600">Limit</th>
                    <th className="text-center py-3 px-4 font-medium text-gray-600">Transaction Mode</th>
                    <th className="text-center py-3 px-4 font-medium text-green-600">Payment Key Mode</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  <tr>
                    <td className="py-3 px-4 text-gray-700">Max response size</td>
                    <td className="text-center py-3 px-4 text-gray-600">1.5 MB</td>
                    <td className="text-center py-3 px-4 text-green-600 font-medium">25 MB</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 text-gray-700">Max file per attachment</td>
                    <td className="text-center py-3 px-4 text-gray-600">5 MB</td>
                    <td className="text-center py-3 px-4 text-gray-600">5 MB</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 text-gray-700">Max total email size</td>
                    <td className="text-center py-3 px-4 text-gray-600">7 MB</td>
                    <td className="text-center py-3 px-4 text-gray-600">7 MB</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 text-gray-700">Max attachments per email</td>
                    <td className="text-center py-3 px-4 text-gray-600">10</td>
                    <td className="text-center py-3 px-4 text-gray-600">10</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* Resource Limits */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Resource Limits (for NEAR Transactions)</h2>
            <p className="text-gray-600 mb-4">
              When calling via NEAR transaction, use these resource limits:
            </p>
            <div className="bg-gray-900 rounded-xl p-4 overflow-x-auto">
              <pre className="text-gray-100 text-sm">
{`{
  "max_memory_mb": 512,
  "max_instructions": 2000000000,
  "max_execution_seconds": 120
}`}
              </pre>
            </div>
          </section>

          {/* Resources */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Resources</h2>
            <div className="grid md:grid-cols-2 gap-4">
              <a
                href="https://outlayer.fastnear.com/payment-keys"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-white rounded-xl border border-gray-200 p-4 hover:border-blue-300 hover:shadow-sm transition-all"
              >
                <h3 className="font-semibold text-gray-900 mb-1">OutLayer Dashboard</h3>
                <p className="text-gray-600 text-sm">Create and manage Payment Keys</p>
              </a>
              <a
                href="https://outlayer.fastnear.com/docs"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-white rounded-xl border border-gray-200 p-4 hover:border-blue-300 hover:shadow-sm transition-all"
              >
                <h3 className="font-semibold text-gray-900 mb-1">OutLayer Documentation</h3>
                <p className="text-gray-600 text-sm">Full API reference and guides</p>
              </a>
              <a
                href="https://github.com/nicetycoon/near-email"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-white rounded-xl border border-gray-200 p-4 hover:border-blue-300 hover:shadow-sm transition-all"
              >
                <h3 className="font-semibold text-gray-900 mb-1">GitHub Repository</h3>
                <p className="text-gray-600 text-sm">Source code and examples</p>
              </a>
              <Link
                href="/docs"
                className="bg-white rounded-xl border border-gray-200 p-4 hover:border-blue-300 hover:shadow-sm transition-all"
              >
                <h3 className="font-semibold text-gray-900 mb-1">How near.email Works</h3>
                <p className="text-gray-600 text-sm">Security and architecture overview</p>
              </Link>
            </div>
          </section>

          {/* Back to app */}
          <div className="text-center pt-6 border-t border-gray-200">
            <Link
              href="/"
              className="inline-flex items-center gap-2 bg-blue-600 text-white px-6 py-2.5 rounded-xl font-medium hover:bg-blue-700 transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              Go to near.email
            </Link>
            <p className="text-gray-400 text-sm mt-4">
              Powered by{' '}
              <a href="https://outlayer.fastnear.com" target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline">
                NEAR Outlayer
              </a>
            </p>
          </div>
        </main>
      </div>
    </>
  );
}
