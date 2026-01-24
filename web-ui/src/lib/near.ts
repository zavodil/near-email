import { setupWalletSelector } from '@near-wallet-selector/core';
import { setupModal } from '@near-wallet-selector/modal-ui';
import { setupMyNearWallet } from '@near-wallet-selector/my-near-wallet';
import { setupHereWallet } from '@near-wallet-selector/here-wallet';
import { setupMeteorWallet } from '@near-wallet-selector/meteor-wallet';
import type { WalletSelector, AccountState } from '@near-wallet-selector/core';
import { actionCreators } from '@near-js/transactions';
import { PrivateKey, decrypt } from 'eciesjs';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

// ECDH + ChaCha20 magic bytes (must match WASM)
const ECDH_MAGIC = new Uint8Array([0x45, 0x43, 0x30, 0x31]); // "EC01"

/**
 * Encrypt data using ECDH + ChaCha20-Poly1305
 *
 * Format: EC01 || ephemeral_pubkey (33 bytes) || nonce (12 bytes) || ciphertext+tag
 *
 * Uses standard ECDH for key agreement, no ECIES library dependencies.
 */
function encryptEcdh(recipientPubkey: Uint8Array, data: Uint8Array): Uint8Array {
  // Generate ephemeral keypair
  const ephemeralPrivkey = secp256k1.utils.randomPrivateKey();
  const ephemeralPubkey = secp256k1.getPublicKey(ephemeralPrivkey, true); // compressed (33 bytes)

  // ECDH: shared_secret = ephemeral_priv * recipient_pub
  const sharedPoint = secp256k1.getSharedSecret(ephemeralPrivkey, recipientPubkey, true);
  // Derive key: SHA256(shared_secret) - skip first byte (prefix) for compatibility
  const sharedX = sharedPoint.slice(1);
  const key = sha256(sharedX);

  // Generate random nonce
  const nonce = randomBytes(12);

  // Encrypt with ChaCha20-Poly1305
  const cipher = chacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(data);

  // Debug: output bytes for comparison with Rust backend
  console.log('[DEBUG] encryptEcdh: recipient_pubkey first 8:', Array.from(recipientPubkey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  console.log('[DEBUG] encryptEcdh: ephemeral_pubkey first 8:', Array.from(ephemeralPubkey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  console.log('[DEBUG] encryptEcdh: shared_x first 8:', Array.from(sharedX.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  console.log('[DEBUG] encryptEcdh: derived key first 8:', Array.from(key.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  console.log('[DEBUG] encryptEcdh: nonce:', Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join(' '));
  console.log('[DEBUG] encryptEcdh: ciphertext first 16:', Array.from(ciphertext.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  console.log('[DEBUG] encryptEcdh: ciphertext last 16 (tag):', Array.from(ciphertext.slice(-16)).map(b => b.toString(16).padStart(2, '0')).join(' '));
  console.log('[DEBUG] encryptEcdh: ciphertext total len:', ciphertext.length);

  // Build output: EC01 || ephemeral_pubkey (33) || nonce (12) || ciphertext
  const output = new Uint8Array(4 + 33 + 12 + ciphertext.length);
  output.set(ECDH_MAGIC, 0);
  output.set(ephemeralPubkey, 4);
  output.set(nonce, 4 + 33);
  output.set(ciphertext, 4 + 33 + 12);

  return output;
}

// Configuration
const NETWORK_ID = process.env.NEXT_PUBLIC_NETWORK_ID || 'mainnet';
const OUTLAYER_API_URL = process.env.NEXT_PUBLIC_OUTLAYER_API_URL || 'https://outlayer.xyz';

// Payment Key localStorage keys
const PAYMENT_KEY_STORAGE = 'near-email-payment-key';
const PAYMENT_KEY_ENABLED_STORAGE = 'near-email-payment-key-enabled';

// Max output size limits (in bytes)
// Transaction mode limited by blockchain (~1.5MB safe)
// HTTPS mode can handle much more (25MB reasonable for browser/memory)
const MAX_OUTPUT_SIZE_TRANSACTION = 1_500_000;  // 1.5 MB
const MAX_OUTPUT_SIZE_HTTPS = 25_000_000;       // 25 MB

// Helper to convert Uint8Array to base64 without stack overflow
// Note: String.fromCharCode(...largeArray) crashes with "Maximum call stack size exceeded" for arrays > ~100KB
function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
const OUTLAYER_CONTRACT = process.env.NEXT_PUBLIC_OUTLAYER_CONTRACT ||
  (NETWORK_ID === 'testnet' ? 'outlayer.testnet' : 'outlayer.near');
const PROJECT_ID = process.env.NEXT_PUBLIC_PROJECT_ID || 'near-email';
const SECRETS_PROFILE = process.env.NEXT_PUBLIC_SECRETS_PROFILE || 'default';
const SECRETS_ACCOUNT_ID = process.env.NEXT_PUBLIC_SECRETS_ACCOUNT_ID || '';
// Whether to include secrets in OutLayer requests (can be disabled after master key migration)
const USE_SECRETS = process.env.NEXT_PUBLIC_USE_SECRETS !== 'false'; // default: true

let selector: WalletSelector | null = null;
let modal: ReturnType<typeof setupModal> | null = null;

// Cached send pubkey for encrypting outgoing emails
// Set by getEmails(), required by sendEmail()
let cachedSendPubkey: string | null = null;

// Cached ephemeral key for requests that return encrypted data
let cachedEphemeralKey: PrivateKey | null = null;

// Payment Key configuration
let paymentKeyConfig: {
  enabled: boolean;
  key: string | null;
  owner: string | null;
} = {
  enabled: false,
  key: null,
  owner: null,
};

// Parse payment key format: owner:nonce:secret
function parsePaymentKey(key: string): { owner: string; nonce: string; secret: string } | null {
  const parts = key.split(':');
  if (parts.length < 3) return null;
  const owner = parts[0];
  const nonce = parts[1];
  const secret = parts.slice(2).join(':'); // In case secret contains ':'
  if (!owner || !nonce || !secret) return null;
  return { owner, nonce, secret };
}

// Parse PROJECT_ID into owner/name for API URL
function parseProjectId(projectId: string): { owner: string; name: string } {
  if (projectId.includes('/')) {
    const [owner, ...rest] = projectId.split('/');
    return { owner, name: rest.join('/') };
  }
  // For PROJECT_ID without owner, assume outlayer contract owner
  return { owner: 'outlayer.near', name: projectId };
}

// Initialize payment key from localStorage
export function initPaymentKey(): void {
  if (typeof window === 'undefined') return;

  const storedKey = localStorage.getItem(PAYMENT_KEY_STORAGE);
  const storedEnabled = localStorage.getItem(PAYMENT_KEY_ENABLED_STORAGE);

  if (storedKey) {
    const parsed = parsePaymentKey(storedKey);
    if (parsed) {
      paymentKeyConfig = {
        enabled: storedEnabled === 'true',
        key: storedKey,
        owner: parsed.owner,
      };
    }
  }
}

// Set payment key (returns false if invalid format)
export function setPaymentKey(key: string | null): boolean {
  if (key === null) {
    paymentKeyConfig = { enabled: false, key: null, owner: null };
    localStorage.removeItem(PAYMENT_KEY_STORAGE);
    localStorage.removeItem(PAYMENT_KEY_ENABLED_STORAGE);
    // Clear cached data since user identity changes
    cachedSendPubkey = null;
    return true;
  }

  const parsed = parsePaymentKey(key);
  if (!parsed) return false;

  paymentKeyConfig = {
    enabled: true,
    key,
    owner: parsed.owner,
  };
  localStorage.setItem(PAYMENT_KEY_STORAGE, key);
  localStorage.setItem(PAYMENT_KEY_ENABLED_STORAGE, 'true');
  // Clear cached data since user identity changes
  cachedSendPubkey = null;
  return true;
}

// Toggle payment key mode
export function setPaymentKeyEnabled(enabled: boolean): void {
  paymentKeyConfig.enabled = enabled && paymentKeyConfig.key !== null;
  if (paymentKeyConfig.enabled) {
    localStorage.setItem(PAYMENT_KEY_ENABLED_STORAGE, 'true');
  } else {
    localStorage.removeItem(PAYMENT_KEY_ENABLED_STORAGE);
  }
  // Clear cached data since user identity may change
  cachedSendPubkey = null;
}

// Get current payment key config for UI
export function getPaymentKeyConfig(): { enabled: boolean; owner: string | null; hasKey: boolean } {
  return {
    enabled: paymentKeyConfig.enabled,
    owner: paymentKeyConfig.owner,
    hasKey: paymentKeyConfig.key !== null,
  };
}

// Check if using payment key mode
export function isPaymentKeyMode(): boolean {
  return paymentKeyConfig.enabled && paymentKeyConfig.key !== null;
}

// Get default max output size based on current mode
function getDefaultMaxOutputSize(): number {
  return isPaymentKeyMode() ? MAX_OUTPUT_SIZE_HTTPS : MAX_OUTPUT_SIZE_TRANSACTION;
}

// Get payment key owner (for display when in payment key mode)
export function getPaymentKeyOwner(): string | null {
  return paymentKeyConfig.owner;
}

export async function initWalletSelector(): Promise<WalletSelector> {
  if (selector) return selector;

  selector = await setupWalletSelector({
    network: NETWORK_ID as 'mainnet' | 'testnet',
    modules: [
      setupMyNearWallet(),
      setupHereWallet(),
      setupMeteorWallet(),
    ],
  });

  modal = setupModal(selector, {
    contractId: OUTLAYER_CONTRACT,
  });

  return selector;
}

export function showModal() {
  if (modal) {
    modal.show();
  }
}

export async function getAccounts(): Promise<AccountState[]> {
  if (!selector) {
    await initWalletSelector();
  }
  return selector!.store.getState().accounts;
}

export async function signOut(): Promise<void> {
  if (!selector) return;
  const wallet = await selector.wallet();
  await wallet.signOut();
}

// Call OutLayer via HTTPS API (Payment Key mode)
async function callOutLayerHttps(action: string, params: Record<string, any>): Promise<any> {
  if (!paymentKeyConfig.key) {
    throw new Error('Payment key not configured');
  }

  const { owner, name } = parseProjectId(PROJECT_ID);

  // Use proxy for localhost to avoid CORS issues
  const isLocalhost = typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');
  const baseUrl = isLocalhost ? '/api/outlayer' : OUTLAYER_API_URL;
  const url = `${baseUrl}/call/${owner}/${name}`;
  console.log('📤 OutLayer HTTPS URL:', url);

  const inputData = {
    action,
    ...params,
  };

  console.log('📤 OutLayer HTTPS input:', inputData);
  console.log('📤 SECRETS_ACCOUNT_ID:', SECRETS_ACCOUNT_ID);
  console.log('📤 SECRETS_PROFILE:', SECRETS_PROFILE);

  // Build request body
  const requestBody: Record<string, any> = {
    input: inputData,
    resource_limits: {
      max_instructions: 2000000000,  // 2B - needed for large attachments decryption
      max_memory_mb: 512,           // 512MB - needed for larger outputs
      max_execution_seconds: 120,   // 2 min - more time for big data
    },
  };

  // Add secrets_ref if configured and enabled
  if (USE_SECRETS && SECRETS_ACCOUNT_ID) {
    requestBody.secrets_ref = {
      profile: SECRETS_PROFILE,
      account_id: SECRETS_ACCOUNT_ID,
    };
  }

  console.log('📤 OutLayer HTTPS requestBody:', JSON.stringify(requestBody, null, 2));

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Payment-Key': paymentKeyConfig.key,
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const errorText = await response.text();
    let errorMessage: string;
    try {
      const errorData = JSON.parse(errorText);
      errorMessage = errorData.error || `HTTP ${response.status}: ${response.statusText}`;
    } catch {
      errorMessage = errorText || `HTTP ${response.status}: ${response.statusText}`;
    }
    throw new Error(errorMessage);
  }

  const result = await response.json();

  if (result.status === 'failed') {
    throw new Error(result.error || 'Execution failed');
  }

  // Parse output - it's a JSON string
  let output = result.output;
  if (typeof output === 'string') {
    try {
      output = JSON.parse(output);
    } catch {
      // Keep as string if not valid JSON
    }
  }

  if (output && !output.success) {
    throw new Error(output.error || 'Unknown error');
  }

  return output;
}

// Call OutLayer via NEAR transaction
// The signer is authenticated via the blockchain transaction (env::signer_account_id() in WASI)
export async function callOutLayer(action: string, params: Record<string, any>): Promise<any> {
  // Route to HTTPS API if payment key mode is enabled
  if (isPaymentKeyMode()) {
    return callOutLayerHttps(action, params);
  }
  const accounts = await getAccounts();
  if (accounts.length === 0) {
    throw new Error('Not connected');
  }

  if (!selector) {
    throw new Error('Wallet not initialized');
  }

  const wallet = await selector.wallet();

  // Build input data for WASI module
  const inputData = JSON.stringify({
    action,
    ...params,
  });

  console.log('📤 OutLayer input_data:', inputData);

  // Build request_execution call
  const requestArgs: Record<string, any> = {
    source: {
      Project: {
        project_id: PROJECT_ID,
        version_key: null,  // Use active version
      },
    },
    input_data: inputData,
    resource_limits: {
      max_instructions: 2000000000, // 2B - needed for large attachments decryption
      max_memory_mb: 512,          // 512MB - needed for large attachments
      max_execution_seconds: 120,  // 2 min for large data
    },
    response_format: 'Json',
  };

  // Add secrets_ref if configured and enabled
  if (USE_SECRETS && SECRETS_ACCOUNT_ID) {
    requestArgs.secrets_ref = {
      profile: SECRETS_PROFILE,
      account_id: SECRETS_ACCOUNT_ID,
    };
  }

  // Create the function call action
  const action_call = actionCreators.functionCall(
    'request_execution',
    requestArgs,
    BigInt('300000000000000'), // 300 TGas
    BigInt('100000000000000000000000') // 0.1 NEAR deposit
  );

  // Send transaction
  const result = await wallet.signAndSendTransaction({
    receiverId: OUTLAYER_CONTRACT,
    actions: [action_call],
  });

  // Extract the result from transaction
  // The result is in the SuccessValue of the final execution outcome
  let successValue: string | null = null;

  if (result && typeof result === 'object') {
    // Try receipts_outcome array (common in NEAR)
    // @ts-ignore
    if (result.receipts_outcome && Array.isArray(result.receipts_outcome)) {
      // @ts-ignore
      for (const receipt of result.receipts_outcome) {
        // @ts-ignore
        if (receipt?.outcome?.status?.SuccessValue) {
          // @ts-ignore
          successValue = receipt.outcome.status.SuccessValue;
          break;
        }
      }
    }

    // Try transaction.outcome
    // @ts-ignore
    if (!successValue && result.transaction?.outcome?.status?.SuccessValue) {
      // @ts-ignore
      successValue = result.transaction.outcome.status.SuccessValue;
    }

    // Try direct status
    // @ts-ignore
    if (!successValue && result.status?.SuccessValue) {
      // @ts-ignore
      successValue = result.status.SuccessValue;
    }
  }

  if (!successValue) {
    throw new Error('No result from OutLayer execution');
  }

  // Decode base64 result
  const decoded = atob(successValue);
  const response = JSON.parse(decoded);

  if (!response.success) {
    throw new Error(response.error || 'Unknown error');
  }

  return response;
}

// Decrypt encrypted_data field using cached ephemeral key
function decryptEmailData(encryptedBase64: string): EmailData {
  if (!cachedEphemeralKey) {
    throw new Error('No ephemeral key available for decryption');
  }

  const encryptedBytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
  const decryptedBytes = decrypt(cachedEphemeralKey.secret, encryptedBytes);
  const decryptedJson = new TextDecoder().decode(decryptedBytes);

  console.log('🔓 Decrypted email data');
  return JSON.parse(decryptedJson) as EmailData;
}

// Combined response with both inbox and sent
export interface GetEmailsResult {
  inbox: Email[];
  sent: SentEmail[];
  sendPubkey: string;
  inboxNextOffset: number | null;
  sentNextOffset: number | null;
}

// API functions

// Get emails (both inbox and sent in one request)
export async function getEmails(
  inboxOffset = 0,
  sentOffset = 0,
  maxOutputSize?: number
): Promise<GetEmailsResult> {
  // Generate ephemeral keypair for this request
  cachedEphemeralKey = new PrivateKey();
  const ephemeralPubkeyHex = cachedEphemeralKey.publicKey.toHex();

  console.log('🔐 Generated ephemeral pubkey:', ephemeralPubkeyHex);

  // Call WASI with ephemeral public key
  const params: Record<string, any> = {
    ephemeral_pubkey: ephemeralPubkeyHex,
    max_output_size: maxOutputSize ?? getDefaultMaxOutputSize(),
  };

  if (inboxOffset > 0) params.inbox_offset = inboxOffset;
  if (sentOffset > 0) params.sent_offset = sentOffset;

  const result = await callOutLayer('get_emails', params);

  // Save send_pubkey for encrypting outgoing emails
  if (result.send_pubkey) {
    cachedSendPubkey = result.send_pubkey;
    console.log('🔑 Cached send_pubkey for outgoing emails');
  }

  // Decrypt the response with ephemeral private key
  const emailData = decryptEmailData(result.encrypted_data);

  return {
    inbox: emailData.inbox,
    sent: emailData.sent,
    sendPubkey: result.send_pubkey,
    inboxNextOffset: result.inbox_next_offset ?? null,
    sentNextOffset: result.sent_next_offset ?? null,
  };
}

/// Get the cached send pubkey (or null if not loaded yet)
export function getSendPubkey(): string | null {
  return cachedSendPubkey;
}

// Send email response with fresh data
export interface SendEmailResult {
  messageId: string | null;
  inbox: Email[];
  sent: SentEmail[];
}

export async function sendEmail(
  to: string,
  subject: string,
  body: string,
  attachments?: Attachment[],
  maxOutputSize?: number
): Promise<SendEmailResult> {
  if (!cachedSendPubkey) {
    throw new Error('Send pubkey not available. Please refresh emails first.');
  }

  // Generate new ephemeral key for response decryption
  cachedEphemeralKey = new PrivateKey();
  const ephemeralPubkeyHex = cachedEphemeralKey.publicKey.toHex();

  // Convert hex pubkey to bytes
  const pubkeyBytes = Uint8Array.from(
    cachedSendPubkey.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
  );

  // Create payload with all email data (to, subject, body, attachments)
  // This keeps recipient address private on-chain
  const payload = {
    to,
    subject,
    body,
    attachments: attachments || [],
  };

  // Encrypt the entire payload with ECDH + ChaCha20-Poly1305
  // No ECIES library - uses standard ECDH for reliable cross-platform compatibility
  const payloadJson = JSON.stringify(payload);
  const encryptedData = encryptEcdh(pubkeyBytes, new TextEncoder().encode(payloadJson));
  const encryptedDataB64 = uint8ArrayToBase64(encryptedData);

  const params: Record<string, any> = {
    encrypted_data: encryptedDataB64,
    ephemeral_pubkey: ephemeralPubkeyHex,
    max_output_size: maxOutputSize ?? getDefaultMaxOutputSize(),
  };

  const result = await callOutLayer('send_email', params);

  // Decrypt fresh email data
  const emailData = decryptEmailData(result.encrypted_data);

  return {
    messageId: result.message_id ?? null,
    inbox: emailData.inbox,
    sent: emailData.sent,
  };
}

// Delete email response with fresh data
export interface DeleteEmailResult {
  deleted: boolean;
  inbox: Email[];
  sent: SentEmail[];
}

export async function deleteEmail(
  emailId: string,
  maxOutputSize?: number
): Promise<DeleteEmailResult> {
  // Generate new ephemeral key for response decryption
  cachedEphemeralKey = new PrivateKey();
  const ephemeralPubkeyHex = cachedEphemeralKey.publicKey.toHex();

  const params: Record<string, any> = {
    email_id: emailId,
    ephemeral_pubkey: ephemeralPubkeyHex,
    max_output_size: maxOutputSize ?? getDefaultMaxOutputSize(),
  };

  const result = await callOutLayer('delete_email', params);

  // Decrypt fresh email data
  const emailData = decryptEmailData(result.encrypted_data);

  return {
    deleted: result.deleted,
    inbox: emailData.inbox,
    sent: emailData.sent,
  };
}

export interface EmailCountResult {
  inboxCount: number;
  sentCount: number;
}

export async function getEmailCount(): Promise<EmailCountResult> {
  const result = await callOutLayer('get_email_count', {});
  return {
    inboxCount: result.inbox_count,
    sentCount: result.sent_count,
  };
}

// Get a single attachment by ID (for lazy loading)
export interface GetAttachmentResult {
  filename: string;
  content_type: string;
  size: number;
  data: string; // base64-encoded attachment content
}

export async function getAttachment(attachmentId: string): Promise<GetAttachmentResult> {
  // Generate ephemeral key for response decryption
  cachedEphemeralKey = new PrivateKey();
  const ephemeralPubkeyHex = cachedEphemeralKey.publicKey.toHex();

  const result = await callOutLayer('get_attachment', {
    attachment_id: attachmentId,
    ephemeral_pubkey: ephemeralPubkeyHex,
  });

  // Decrypt the attachment data
  const encryptedBytes = Uint8Array.from(atob(result.encrypted_data), c => c.charCodeAt(0));
  const decryptedBytes = decrypt(cachedEphemeralKey.secret, encryptedBytes);
  const data = uint8ArrayToBase64(decryptedBytes);

  return {
    filename: result.filename,
    content_type: result.content_type,
    size: result.size,
    data,
  };
}

// Types
export interface Attachment {
  filename: string;
  content_type: string;
  data?: string; // base64-encoded (for small attachments < 2KB)
  size: number;
  attachment_id?: string; // For lazy loading (large attachments >= 2KB)
}

export interface Email {
  id: string;
  from: string;
  subject: string;
  body: string;
  received_at: string;
  attachments?: Attachment[];
}

export interface SentEmail {
  id: string;
  to: string;
  subject: string;
  body: string;
  tx_hash: string | null;
  sent_at: string;
  attachments?: Attachment[];
}

// Combined data returned in encrypted payload
export interface EmailData {
  inbox: Email[];
  sent: SentEmail[];
}
