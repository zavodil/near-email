# Deployment Guide for near.email

Step-by-step instructions for deploying near.email to production.

## Requirements

- VPS with open port 25 (Hetzner, OVH, Vultr — **not** AWS/GCP/Azure)
- Domain (e.g., `near.email`)
- Docker + Docker Compose
- Rust toolchain (for building WASI module)

## Step 1: Server Setup

### 1.1 Rent a VPS

Recommended providers with open port 25:

| Provider | Plan | Price |
|----------|------|-------|
| Hetzner Cloud | CX21 | ~€5/mo |
| OVH | VPS Starter | ~€4/mo |
| Vultr | Cloud Compute | ~$5/mo |

### 1.2 Install Dependencies

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y \
    docker.io \
    docker-compose \
    git \
    curl

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### 1.3 Install Rust (for WASI build)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add wasm32-wasip2
```

## Step 2: DNS Configuration

Add DNS records for your domain:

```dns
# MX record — where to deliver mail
near.email.              MX     10    mail.near.email.

# A record — your server IP
mail.near.email.         A      YOUR_SERVER_IP

# A record for web interface
near.email.              A      YOUR_SERVER_IP

# SPF — authorize server to send mail
near.email.              TXT    "v=spf1 ip4:YOUR_SERVER_IP -all"

# DMARC — policy for failed checks
_dmarc.near.email.       TXT    "v=DMARC1; p=quarantine; rua=mailto:admin@near.email"
```

**Wait 5-10 minutes** for DNS propagation.

Verify:
```bash
dig MX near.email
dig A mail.near.email
```

## Step 3: Clone and Configure

### 3.1 Clone Repository

```bash
cd /opt
git clone https://github.com/zavodil/near-email.git
cd near-email
```

### 3.2 Generate Master Keys

```bash
./scripts/generate_keys.sh | tee keys.txt
```

Output will contain:
```
# Add to OutLayer secrets:
MASTER_PRIVATE_KEY=a1b2c3d4...

# Add to smtp-server/.env:
MASTER_PUBLIC_KEY=02a1b2c3d4...
```

**IMPORTANT:** Store `MASTER_PRIVATE_KEY` securely!

### 3.3 Set Environment Variables

```bash
# Create .env file
cat > .env << EOF
# Public key for SMTP server
MASTER_PUBLIC_KEY=02a1b2c3d4...your_public_key

# OutLayer API URL (for web interface)
OUTLAYER_API_URL=https://outlayer.xyz
EOF
```

### 3.4 Configure SMTP Server

```bash
cp smtp-server/.env.example smtp-server/.env
```

Edit `smtp-server/.env`:
```env
DATABASE_URL=postgres://near_email:near_email_secret@postgres:5432/near_email
MASTER_PUBLIC_KEY=02a1b2c3d4...your_public_key
SMTP_HOST=0.0.0.0
SMTP_PORT=25
EMAIL_DOMAIN=near.email
```

## Step 4: Build WASI Module

```bash
cd wasi-near-email-ark
./build.sh
```

Output: `target/wasm32-wasip2/release/wasi-near-email-ark.wasm`

## Step 5: Deploy to OutLayer

### 5.1 Create Project in OutLayer

```bash
# Via CLI or dashboard
near call outlayer.near create_project '{
  "project_id": "near-email",
  "code_source": {
    "repo": "https://github.com/your-org/near-email",
    "commit": "main",
    "path": "wasi-near-email-ark",
    "build_target": "wasm32-wasip2"
  }
}' --accountId your.near --deposit 1
```

### 5.2 Add Secrets

In OutLayer dashboard or via API, add secrets for the project:

| Secret Name | Value |
|-------------|-------|
| `MASTER_PRIVATE_KEY` | `a1b2c3d4...` (private key) |
| `DATABASE_API_URL` | `https://mail.near.email:8080` |

## Step 6: Start Services

### 6.1 Start with Docker Compose

```bash
cd /opt/near-email

# Start all services
docker-compose up -d

# Check status
docker-compose ps
```

Services should be running:
- `postgres` — database
- `smtp-server` — SMTP on port 25
- `db-api` — HTTP API on port 8080
- `web-ui` — web interface on port 3000

### 6.2 Check Logs

```bash
# All logs
docker-compose logs -f

# SMTP server only
docker-compose logs -f smtp-server
```

## Step 7: Configure HTTPS (Nginx + Let's Encrypt)

### 7.1 Install Nginx and Certbot

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

### 7.2 Configure Nginx

```bash
sudo tee /etc/nginx/sites-available/near-email << 'EOF'
# Web UI
server {
    listen 80;
    server_name near.email;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }
}

# DB API (internal, but exposed for WASI)
server {
    listen 80;
    server_name mail.near.email;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/near-email /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 7.3 Obtain SSL Certificates

```bash
sudo certbot --nginx -d near.email -d mail.near.email
```

## Step 8: Testing

### 8.1 Test SMTP

```bash
# Send test email
echo "Test email body" | mail -s "Test Subject" test@near.email

# Or via telnet
telnet mail.near.email 25
HELO test
MAIL FROM:<test@example.com>
RCPT TO:<alice@near.email>
DATA
Subject: Test

Hello from test!
.
QUIT
```

### 8.2 Test Web Interface

Open `https://near.email` in browser:
1. Connect NEAR wallet
2. You should see the test email in inbox

### 8.3 Test OutLayer API

```bash
curl -X POST https://api.outlayer.fastnear.com/call/zavodil.near/near-email \
  -H "Content-Type: application/json" \
  -d '{
    "action": "get_email_count",
    "account_id": "alice.near",
    "signature": "...",
    "public_key": "ed25519:...",
    "message": "near-email:get_email_count:1234567890"
  }'
```

## Step 9: Monitoring

### 9.1 Auto-restart

Docker Compose is already configured for restart. For systemd:

```bash
sudo tee /etc/systemd/system/near-email.service << 'EOF'
[Unit]
Description=NEAR Email Services
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/near-email
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable near-email
sudo systemctl start near-email
```

### 9.2 Logging

```bash
# View logs in real-time
docker-compose logs -f --tail=100

# Save logs to file
docker-compose logs > /var/log/near-email.log
```

## Troubleshooting

### Port 25 Blocked

```bash
# Check port
sudo netstat -tlnp | grep 25

# Check firewall
sudo ufw status
sudo ufw allow 25/tcp
```

### Emails Not Arriving

1. Check DNS MX record: `dig MX near.email`
2. Check SMTP logs: `docker-compose logs smtp-server`
3. Check SPF: `dig TXT near.email`

### Database Connection Error

```bash
# Check PostgreSQL
docker-compose logs postgres

# Connect to database
docker-compose exec postgres psql -U near_email -d near_email
```

### WASI Module Not Working

1. Check secrets in OutLayer dashboard
2. Verify database URL is accessible from internet
3. Check OutLayer logs

## Updates

```bash
cd /opt/near-email

# Pull updates
git pull

# Rebuild images
docker-compose build

# Restart
docker-compose up -d

# For WASI module — rebuild and redeploy
cd wasi-near-email-ark
./build.sh
# Update in OutLayer
```

## Backup

```bash
# Backup database
docker-compose exec postgres pg_dump -U near_email near_email > backup.sql

# Restore
cat backup.sql | docker-compose exec -T postgres psql -U near_email near_email
```
