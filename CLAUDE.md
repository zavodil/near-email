# CLAUDE.md - near.email

## Project Overview

**near.email** - end-to-end encrypted email service for NEAR blockchain accounts. Every NEAR account automatically has an email address (e.g., `alice.near` → `alice@near.email`).

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Web UI    │────▶│   OutLayer  │────▶│ WASI Module │
│  (Next.js)  │     │  (Testnet)  │     │   (TEE)     │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                    ┌─────────────┐     ┌──────▼──────┐
                    │ SMTP Server │────▶│   DB API    │
                    │ (Incoming)  │     │  (HTTP)     │
                    └─────────────┘     └──────┬──────┘
                                               │
                                        ┌──────▼──────┐
                                        │  PostgreSQL │
                                        └─────────────┘
```

## Components

| Directory | Description | Language |
|-----------|-------------|----------|
| `wasi-near-email-ark/` | WASI module - encryption/decryption, email parsing | Rust |
| `smtp-server/` | Incoming SMTP server - receives external emails | Rust |
| `db-api/` | HTTP API for database + outgoing SMTP relay | Rust |
| `web-ui/` | Frontend application | TypeScript/Next.js |
| `scripts/` | Utility scripts (keygen) | Rust |

## Critical Rules

### NEVER Do
- **Don't modify encryption logic** without understanding ECIES flow
- **Don't change database schema** without updating all components
- **Don't expose private keys** in logs or responses
- **Don't skip attachment size limits** (10MB per file, 40MB total, 50MB email)

### Security Model
1. **Master key** stored in TEE, never exposed
2. **User keys** derived: `user_privkey = master_privkey + SHA256(account_id)`
3. **ECIES encryption** for all email content
4. **Ephemeral keys** for each request/response

### Code Patterns

```rust
// CORRECT - propagate errors to user
anyhow::bail!("Email too large: {} bytes exceeds 50MB limit", size);

// WRONG - silent failure, user sees nothing
tracing::warn!("Email too large");
return Ok(());
```

## Commands

```bash
# Build all components
cd wasi-near-email-ark && cargo build --release --target wasm32-wasip2
cd smtp-server && cargo build --release
cd db-api && cargo build --release
cd web-ui && npm run build

# Run locally
cd db-api && cargo run          # Port 8080
cd smtp-server && cargo run     # Port 25
cd web-ui && npm run dev        # Port 3000

# Deploy WASI to OutLayer
cd ../.. && cargo run -p upload-fastfs -- \
  --project-id "account.near/near-email" \
  --file wasi-examples/near-email/wasi-near-email-ark/target/wasm32-wasip2/release/wasi_near_email_ark.wasm
```

## Environment Variables

### WASI Module (secrets in OutLayer)
| Variable | Required | Description |
|----------|----------|-------------|
| `PROTECTED_MASTER_KEY` | Yes | Hex-encoded secp256k1 private key |
| `DATABASE_API_URL` | Yes | URL to db-api (e.g., `http://db-api:8080`) |
| `DEFAULT_ACCOUNT_SUFFIX` | No | `.near` or `.testnet` |
| `EMAIL_SIGNATURE` | No | Signature template with `%account%` placeholder |

### SMTP Server
| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `MASTER_PUBLIC_KEY` | Yes | Hex-encoded secp256k1 public key |
| `SMTP_HOST` | No | Bind address (default: `0.0.0.0`) |
| `SMTP_PORT` | No | Port (default: `25`) |

### DB API
| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `API_PORT` | No | Port (default: `8080`) |
| `DKIM_PRIVATE_KEY` | No | RSA PEM for DKIM signing |
| `DKIM_SELECTOR` | No | DKIM selector (default: `mail`) |
| `EMAIL_SIGNATURE` | No | Signature for outgoing emails |

### Web UI
| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_NETWORK_ID` | `mainnet` | NEAR network |
| `NEXT_PUBLIC_OUTLAYER_API_URL` | - | OutLayer API endpoint |
| `NEXT_PUBLIC_PROJECT_ID` | `near-email` | OutLayer project ID |

## Key Files

### WASI Module
- `src/main.rs` - Request handlers, email parsing, MIME building
- `src/types.rs` - API types, Email/Attachment structs
- `src/crypto.rs` - ECIES encryption/decryption
- `src/db.rs` - HTTP client for db-api

### Web UI
- `src/lib/near.ts` - NEAR wallet, OutLayer calls, encryption
- `src/pages/index.tsx` - Main email interface
- `src/components/ComposeModal.tsx` - Email composition with attachments
- `src/components/EmailView.tsx` - Email display with download

## Data Flow

### Receiving Email (External → User)
1. SMTP server receives email (up to 50MB)
2. Encrypts with user's derived public key
3. Stores encrypted blob in PostgreSQL
4. User calls `get_emails` via OutLayer
5. WASI decrypts with user's derived private key
6. Returns decrypted emails with attachments

### Sending Email (User → External)
1. UI encrypts subject/body/attachments with user's public key
2. Calls `send_email` via OutLayer
3. WASI decrypts content
4. For `@near.email`: stores encrypted for recipient
5. For external: calls db-api `/send` endpoint
6. db-api builds MIME multipart, sends via SMTP

## Testing

```bash
# Send test email to NEAR account
echo "Test body" | mail -s "Test" alice@near.email

# Check WASI module (mainnet only — near-email is not deployed on testnet
# because email addresses are based on mainnet .near accounts)
curl -X POST https://api.outlayer.fastnear.com/call/zavodil.near/near-email \
  -H "X-Payment-Key: owner:1:secret" \
  -H "Content-Type: application/json" \
  -d '{"action": "get_emails"}'
```

## Common Issues

1. **"Send pubkey not available"** - User must call `get_emails` first to cache encryption key
2. **Email not decrypting** - Check account suffix matches (`.near` vs `.testnet`)
3. **Attachments missing** - Verify db-api has `attachments` in `SendEmailBody`
4. **DKIM failing** - Ensure `DKIM_PRIVATE_KEY` has proper PEM format with `\n`
