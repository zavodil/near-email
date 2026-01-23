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

// API functions
export async function getEmails(limit = 50, offset = 0): Promise<Email[]> {
  // Generate ephemeral keypair for this request
  // The private key never leaves the browser
  const ephemeralKey = new PrivateKey();
  const ephemeralPubkeyHex = ephemeralKey.publicKey.toHex();

  console.log('🔐 Generated ephemeral pubkey:', ephemeralPubkeyHex);

  // Call WASI with ephemeral public key
  const result = await callOutLayer('get_emails', {
    ephemeral_pubkey: ephemeralPubkeyHex,
    limit,
    offset,
  });

  // Save send_pubkey for encrypting outgoing emails
  if (result.send_pubkey) {
    cachedSendPubkey = result.send_pubkey;
    console.log('🔑 Cached send_pubkey for outgoing emails');
  }

  // Decrypt the response with ephemeral private key
  const encryptedBase64 = result.encrypted_emails;
  const encryptedBytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

  const decryptedBytes = decrypt(ephemeralKey.secret, encryptedBytes);
  const decryptedJson = new TextDecoder().decode(decryptedBytes);

  console.log('🔓 Decrypted emails');

  return JSON.parse(decryptedJson) as Email[];
}

/// Get the cached send pubkey (or null if not loaded yet)
export function getSendPubkey(): string | null {
  return cachedSendPubkey;
}

export async function sendEmail(to: string, subject: string, body: string): Promise<void> {
  if (!cachedSendPubkey) {
    throw new Error('Send pubkey not available. Please refresh emails first.');
  }

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

  await callOutLayer('send_email', {
    to,
    encrypted_subject: encryptedSubjectB64,
    encrypted_body: encryptedBodyB64,
  });
}

export async function deleteEmail(emailId: string): Promise<boolean> {
  const result = await callOutLayer('delete_email', { email_id: emailId });
  return result.deleted;
}

export async function getEmailCount(): Promise<number> {
  const result = await callOutLayer('get_email_count', {});
  return result.count;
}

export async function getSentEmails(limit = 50, offset = 0): Promise<SentEmail[]> {
  // Generate ephemeral keypair for this request
  const ephemeralKey = new PrivateKey();
  const ephemeralPubkeyHex = ephemeralKey.publicKey.toHex();

  console.log('🔐 Generated ephemeral pubkey for sent emails:', ephemeralPubkeyHex);

  // Call WASI with ephemeral public key
  const result = await callOutLayer('get_sent_emails', {
    ephemeral_pubkey: ephemeralPubkeyHex,
    limit,
    offset,
  });

  // Decrypt the response with ephemeral private key
  const encryptedBase64 = result.encrypted_emails;
  const encryptedBytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

  const decryptedBytes = decrypt(ephemeralKey.secret, encryptedBytes);
  const decryptedJson = new TextDecoder().decode(decryptedBytes);

  console.log('🔓 Decrypted sent emails');

  return JSON.parse(decryptedJson) as SentEmail[];
}

// Types
export interface Email {
  id: string;
  from: string;
  subject: string;
  body: string;
  received_at: string;
}

export interface SentEmail {
  id: string;
  to: string;
  subject: string;
  body: string;
  tx_hash: string | null;
  sent_at: string;
}
