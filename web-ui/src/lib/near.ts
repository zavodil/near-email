import { setupWalletSelector } from '@near-wallet-selector/core';
import { setupModal } from '@near-wallet-selector/modal-ui';
import { setupMyNearWallet } from '@near-wallet-selector/my-near-wallet';
import { setupHereWallet } from '@near-wallet-selector/here-wallet';
import { setupMeteorWallet } from '@near-wallet-selector/meteor-wallet';
import type { WalletSelector, AccountState } from '@near-wallet-selector/core';
import { actionCreators } from '@near-js/transactions';
import { PrivateKey, decrypt, encrypt } from 'eciesjs';

// Configuration
const NETWORK_ID = process.env.NEXT_PUBLIC_NETWORK_ID || 'mainnet';
const OUTLAYER_CONTRACT = process.env.NEXT_PUBLIC_OUTLAYER_CONTRACT ||
  (NETWORK_ID === 'testnet' ? 'outlayer.testnet' : 'outlayer.near');
const PROJECT_ID = process.env.NEXT_PUBLIC_PROJECT_ID || 'near-email';
const SECRETS_PROFILE = process.env.NEXT_PUBLIC_SECRETS_PROFILE || 'default';
const SECRETS_ACCOUNT_ID = process.env.NEXT_PUBLIC_SECRETS_ACCOUNT_ID || '';

let selector: WalletSelector | null = null;
let modal: ReturnType<typeof setupModal> | null = null;

// Cached send pubkey for encrypting outgoing emails
// Set by getEmails(), required by sendEmail()
let cachedSendPubkey: string | null = null;

// Cached ephemeral key for requests that return encrypted data
let cachedEphemeralKey: PrivateKey | null = null;

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

// Call OutLayer via NEAR transaction
// The signer is authenticated via the blockchain transaction (env::signer_account_id() in WASI)
export async function callOutLayer(action: string, params: Record<string, any>): Promise<any> {
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
      max_instructions: 100000000, // 100M instructions
      max_memory_mb: 128,
      max_execution_seconds: 60,
    },
    response_format: 'Json',
  };

  // Add secrets_ref if configured
  if (SECRETS_ACCOUNT_ID) {
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
  };

  if (inboxOffset > 0) params.inbox_offset = inboxOffset;
  if (sentOffset > 0) params.sent_offset = sentOffset;
  if (maxOutputSize) params.max_output_size = maxOutputSize;

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

  // Encrypt subject and body with user's public key
  const encryptedSubject = encrypt(pubkeyBytes, new TextEncoder().encode(subject));
  const encryptedBody = encrypt(pubkeyBytes, new TextEncoder().encode(body));

  // Convert to base64
  const encryptedSubjectB64 = btoa(String.fromCharCode(...encryptedSubject));
  const encryptedBodyB64 = btoa(String.fromCharCode(...encryptedBody));

  const params: Record<string, any> = {
    to,
    encrypted_subject: encryptedSubjectB64,
    encrypted_body: encryptedBodyB64,
    ephemeral_pubkey: ephemeralPubkeyHex,
  };

  // Encrypt attachments if present
  if (attachments && attachments.length > 0) {
    const attachmentsJson = JSON.stringify(attachments);
    const encryptedAttachments = encrypt(pubkeyBytes, new TextEncoder().encode(attachmentsJson));
    params.encrypted_attachments = btoa(String.fromCharCode(...encryptedAttachments));
  }

  if (maxOutputSize) params.max_output_size = maxOutputSize;

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
  };

  if (maxOutputSize) params.max_output_size = maxOutputSize;

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

// Types
export interface Attachment {
  filename: string;
  content_type: string;
  data: string; // base64-encoded
  size: number;
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
