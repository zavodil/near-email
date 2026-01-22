# NEAR Email

Blockchain-native email for NEAR accounts. Every NEAR account automatically has an email address: `alice.near` -> `alice@near.email`

## Architecture

```
External World (Gmail, etc.)
        │
        │ SMTP (port 25)
        ▼
┌─────────────────────────────────────────┐
│        smtp-server (Rust)               │
│  - Receives *@near.email                │
│  - Derives public key from account_id   │
│  - Encrypts email with ECIES            │
│  - Stores encrypted blob in PostgreSQL  │
└─────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────┐
│        PostgreSQL                       │
│  - Encrypted emails (only owner decrypt)│
└─────────────────────────────────────────┘
        │
        │ HTTP API
        ▼
┌─────────────────────────────────────────┐
│        OutLayer TEE                     │
│  - Verifies NEAR signature              │
│  - Derives private key from master      │
│  - Decrypts emails for owner            │
└─────────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────────┐
│        web-ui (Next.js)                 │
│  - Connect NEAR wallet                  │
│  - Sign message to prove ownership      │
│  - View decrypted inbox                 │
└─────────────────────────────────────────┘
```

## Components

| Directory | Description |
|-----------|-------------|
| `smtp-server/` | Rust SMTP server that receives and encrypts emails |
| `wasi-near-email-ark/` | OutLayer WASI module for decryption |
| `db-api/` | HTTP API for database access from WASI |
| `web-ui/` | Next.js frontend for inbox |
| `scripts/` | Key generation utilities |

## Key Derivation (BIP32-style)

The critical feature: SMTP server can derive public keys WITHOUT knowing the master secret.

```
Master Keypair (generated once in TEE):
  master_private_key → stored in OutLayer secrets
  master_public_key  → published, available to SMTP server

Public Key Derivation (SMTP server, no secret needed):
  user_pubkey = master_pubkey + SHA256("near-email:v1:" + account_id) * G

Private Key Derivation (OutLayer TEE, requires secret):
  user_privkey = master_privkey + SHA256("near-email:v1:" + account_id)
```

## Quick Start

### Option A: Docker Compose (Recommended)

```bash
# 1. Generate master keypair
./scripts/generate_keys.sh > keys.txt

# 2. Set environment variable
export MASTER_PUBLIC_KEY=<from keys.txt>

# 3. Run everything
docker-compose up -d
```

### Option B: Manual Setup

#### 1. Generate Keys

```bash
./scripts/generate_keys.sh
# Save PROTECTED_MASTER_KEY for OutLayer secrets
# Save MASTER_PUBLIC_KEY for smtp-server/.env
```

#### 2. Run SMTP Server

```bash
cd smtp-server
cp .env.example .env
# Edit .env with your settings
cargo run
```

#### 3. Run DB API

```bash
cd db-api
DATABASE_URL=postgres://... cargo run
```

#### 4. Deploy WASI Module

```bash
cd wasi-near-email-ark
./build.sh
# Deploy to OutLayer with secrets:
#   PROTECTED_MASTER_KEY=...
#   DATABASE_API_URL=https://your-db-api-url
```

#### 5. Run Web UI

```bash
cd web-ui
npm install
npm run dev
```

## Environment Variables

### smtp-server

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `MASTER_PUBLIC_KEY` | Hex-encoded secp256k1 public key |
| `SMTP_PORT` | SMTP listen port (default: 25) |

### wasi-near-email-ark (OutLayer secrets)

| Variable | Description |
|----------|-------------|
| `PROTECTED_MASTER_KEY` | Hex-encoded secp256k1 private key |
| `DATABASE_API_URL` | HTTP API URL for database access |

## DNS Configuration

```dns
near.email.              MX     10    mail.near.email.
mail.near.email.         A      <your-server-ip>
near.email.              TXT    "v=spf1 ip4:<your-server-ip> -all"
```

## Security Model

- **Server compromise**: Emails encrypted, server only has public key
- **Master key leak**: Key stored only in OutLayer TEE
- **Spam**: Rate limiting before encryption
- **Impersonation**: DKIM/SPF/DMARC for outgoing mail

## Production Deployment

See [DEPLOY.md](DEPLOY.md) for full deployment guide including:
- VPS setup (Hetzner/OVH/Vultr)
- DNS configuration
- SSL certificates
- OutLayer secrets
- Monitoring and backups
