# PROJECT.md - near.email Technical Specification

## Overview

**near.email** provides blockchain-native email for NEAR accounts with end-to-end encryption. Users authenticate via NEAR wallet signatures - no registration required.

### Key Features
- Automatic email address for every NEAR account
- End-to-end encryption (only recipient can read)
- Attachments up to 50MB per email
- Internal (NEAR-to-NEAR) and external email support
- DKIM signing for deliverability

## Cryptographic Design

### Key Derivation
```
Master Key (stored in TEE)
    │
    ▼
User Key = Master + SHA256(account_id)
    │
    ├── alice.near  → unique keypair
    ├── bob.near    → unique keypair
    └── ...
```

### Encryption Flow
```
Sender                          Recipient
   │                                │
   │  1. Get recipient's pubkey     │
   │     (derived from master)      │
   │                                │
   │  2. ECIES encrypt content      │
   │     with recipient pubkey      │
   │                                │
   │  3. Store encrypted blob       │
   │                                │
   │                                │  4. Request emails
   │                                │     (signed by wallet)
   │                                │
   │                                │  5. WASI derives privkey
   │                                │     from master + account_id
   │                                │
   │                                │  6. Decrypt and return
```

### Response Encryption
Each API response is encrypted with an ephemeral key pair:
1. Client generates ephemeral keypair
2. Sends ephemeral public key with request
3. Server encrypts response with ephemeral pubkey
4. Client decrypts with ephemeral private key

## API Specification

### WASI Module Requests

#### GetEmails
```json
{
  "get_emails": {
    "ephemeral_pubkey": "hex-encoded-33-bytes",
    "inbox_offset": 0,
    "sent_offset": 0,
    "max_output_size": 1500000
  }
}
```

Response:
```json
{
  "encrypted_data": "base64-ecies-ciphertext",
  "send_pubkey": "hex-user-pubkey-for-sending",
  "inbox_next_offset": null,
  "sent_next_offset": 10
}
```

Decrypted `encrypted_data`:
```json
{
  "inbox": [
    {
      "id": "uuid",
      "from": "sender@example.com",
      "subject": "Hello",
      "body": "Email content",
      "received_at": "2024-01-15T10:30:00Z",
      "attachments": [
        {
          "filename": "doc.pdf",
          "content_type": "application/pdf",
          "data": "base64-content",
          "size": 12345
        }
      ]
    }
  ],
  "sent": [...]
}
```

#### SendEmail
```json
{
  "send_email": {
    "to": "recipient@example.com",
    "encrypted_subject": "base64-ecies-ciphertext",
    "encrypted_body": "base64-ecies-ciphertext",
    "encrypted_attachments": "base64-ecies-ciphertext-of-json-array",
    "ephemeral_pubkey": "hex-encoded-33-bytes",
    "max_output_size": 1500000
  }
}
```

#### DeleteEmail
```json
{
  "delete_email": {
    "email_id": "uuid",
    "ephemeral_pubkey": "hex-encoded-33-bytes"
  }
}
```

### DB API Endpoints

#### GET /emails
Query: `?recipient={account_id}&limit={n}&offset={n}`

#### POST /send
```json
{
  "from_account": "alice.near",
  "to": "bob@gmail.com",
  "subject": "Hello",
  "body": "Message content",
  "attachments": [
    {
      "filename": "photo.jpg",
      "content_type": "image/jpeg",
      "data": "base64-content",
      "size": 54321
    }
  ]
}
```

#### POST /internal-store
For NEAR-to-NEAR emails (already encrypted by WASI).

#### DELETE /emails/{id}
Body: `{"account_id": "alice.near"}`

## Database Schema

```sql
-- Incoming emails (encrypted)
CREATE TABLE emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient VARCHAR(64) NOT NULL,      -- NEAR account_id
    sender_email VARCHAR(255) NOT NULL,
    encrypted_data BYTEA NOT NULL,       -- ECIES ciphertext
    received_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_emails_recipient ON emails(recipient);

-- Sent emails (encrypted, for sender's "Sent" folder)
CREATE TABLE sent_emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender VARCHAR(64) NOT NULL,         -- NEAR account_id
    recipient_email VARCHAR(255) NOT NULL,
    encrypted_data BYTEA NOT NULL,
    tx_hash VARCHAR(64),                 -- NEAR transaction hash (internal only)
    sent_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_sent_emails_sender ON sent_emails(sender);
```

## Email Format

### Simple Text Email
```
From: alice@near.email
To: bob@gmail.com
Subject: Hello
Content-Type: text/plain; charset=utf-8

Message body here.
```

### Multipart with Attachments
```
From: alice@near.email
To: bob@gmail.com
Subject: Photos
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_abc123"

------=_Part_abc123
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

Check out these photos!

------=_Part_abc123
Content-Type: image/jpeg; name="photo.jpg"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="photo.jpg"

/9j/4AAQSkZJRgABAQEASABIAAD...

------=_Part_abc123--
```

## Size Limits

| Limit | Value | Location |
|-------|-------|----------|
| Max email size (incoming) | 50 MB | smtp-server |
| Max attachment per file | 10 MB | web-ui |
| Max total attachments | 40 MB | web-ui |
| Max API response | 1.5 MB | wasi module |
| Truncated email placeholder | ~100 bytes | wasi module |

### Large Email Handling
When email exceeds response limit:
1. Show subject/sender normally
2. Replace body with: `[Email too large to display in this view]`
3. Add note: `[N attachment(s) not shown]`
4. Return `inbox_next_offset` for pagination

## Implementation Status

### Completed
- [x] SMTP server with 50MB limit
- [x] Email encryption/decryption
- [x] Attachment support (receive)
- [x] Attachment support (send internal)
- [x] Attachment support (send external via SMTP)
- [x] Large email truncation
- [x] Pagination (offset-based)
- [x] DKIM signing
- [x] Web UI with modern design
- [x] Toast notifications
- [x] Reply functionality
- [x] Delete functionality

### Future Enhancements
- [ ] Search functionality
- [ ] Folders/labels
- [ ] Draft support
- [ ] Read/unread status
- [ ] Multiple recipients (CC/BCC)
- [ ] HTML email rendering
- [ ] Contact list
- [ ] Email forwarding rules

## Deployment

### Production Setup
1. Deploy PostgreSQL with schema
2. Deploy db-api with DATABASE_URL + DKIM keys
3. Deploy smtp-server with DATABASE_URL + MASTER_PUBLIC_KEY
4. Configure DNS: MX record → smtp-server
5. Configure DNS: DKIM TXT record
6. Upload WASI module to OutLayer
7. Configure OutLayer secrets (PROTECTED_MASTER_KEY, DATABASE_API_URL)
8. Deploy web-ui with NEXT_PUBLIC_* env vars

### DNS Records
```
; MX record for incoming email
near.email.    IN  MX  10 mail.near.email.
mail.near.email. IN A  <smtp-server-ip>

; DKIM for outgoing email signing
mail._domainkey.near.email. IN TXT "v=DKIM1; k=rsa; p=<public-key>"

; SPF for sender verification
near.email.    IN  TXT "v=spf1 ip4:<smtp-server-ip> -all"

; DMARC policy
_dmarc.near.email. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@near.email"
```

## Security Considerations

1. **Private keys never leave TEE** - Master key in OutLayer secrets
2. **Account verification** - NEAR wallet signature required
3. **No plaintext storage** - All emails encrypted at rest
4. **Ephemeral response keys** - Forward secrecy for API responses
5. **Input validation** - Size limits, email format validation
6. **Rate limiting** - Implement at API gateway level
7. **DKIM/SPF/DMARC** - Email authentication for deliverability
