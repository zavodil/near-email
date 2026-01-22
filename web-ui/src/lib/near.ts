import { setupWalletSelector } from '@near-wallet-selector/core';
import { setupModal } from '@near-wallet-selector/modal-ui';
import { setupMyNearWallet } from '@near-wallet-selector/my-near-wallet';
import { setupHereWallet } from '@near-wallet-selector/here-wallet';
import { setupMeteorWallet } from '@near-wallet-selector/meteor-wallet';
import type { WalletSelector, AccountState } from '@near-wallet-selector/core';

// Configuration
const NETWORK_ID = process.env.NEXT_PUBLIC_NETWORK_ID || 'mainnet';
const OUTLAYER_API_URL = process.env.NEXT_PUBLIC_OUTLAYER_API_URL || 'https://outlayer.xyz';
const PROJECT_ID = process.env.NEXT_PUBLIC_PROJECT_ID || 'near-email';

let selector: WalletSelector | null = null;
let modal: ReturnType<typeof setupModal> | null = null;

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
    contractId: '', // No contract interaction needed
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

// Sign a message for authentication
export async function signMessage(message: string): Promise<{
  signature: string;
  publicKey: string;
}> {
  if (!selector) {
    throw new Error('Wallet not initialized');
  }

  const wallet = await selector.wallet();
  const accounts = await wallet.getAccounts();

  if (accounts.length === 0) {
    throw new Error('No account connected');
  }

  // Use wallet's signMessage if available, otherwise use a workaround
  if ('signMessage' in wallet) {
    const result = await (wallet as any).signMessage({
      message,
      recipient: accounts[0].accountId,
      nonce: Buffer.from(new Uint8Array(32)),
    });
    return {
      signature: result.signature,
      publicKey: result.publicKey,
    };
  }

  throw new Error('Wallet does not support message signing');
}

// Call OutLayer API
export async function callOutLayer(action: string, params: Record<string, any>): Promise<any> {
  const accounts = await getAccounts();
  if (accounts.length === 0) {
    throw new Error('Not connected');
  }

  const accountId = accounts[0].accountId;
  const timestamp = Math.floor(Date.now() / 1000);
  const message = `near-email:${action}:${timestamp}`;

  // Sign the message
  const { signature, publicKey } = await signMessage(message);

  // Build request
  const requestBody = {
    action,
    account_id: accountId,
    signature,
    public_key: publicKey,
    message,
    ...params,
  };

  // Call OutLayer API
  const response = await fetch(`${OUTLAYER_API_URL}/execute/${PROJECT_ID}/mail`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    throw new Error(`OutLayer API error: ${response.status}`);
  }

  const result = await response.json();

  if (!result.success) {
    throw new Error(result.error || 'Unknown error');
  }

  return result;
}

// API functions
export async function getEmails(limit = 50, offset = 0): Promise<Email[]> {
  const result = await callOutLayer('get_emails', { limit, offset });
  return result.emails || [];
}

export async function sendEmail(to: string, subject: string, body: string): Promise<void> {
  await callOutLayer('send_email', { to, subject, body });
}

export async function deleteEmail(emailId: string): Promise<boolean> {
  const result = await callOutLayer('delete_email', { email_id: emailId });
  return result.deleted;
}

export async function getEmailCount(): Promise<number> {
  const result = await callOutLayer('get_email_count', {});
  return result.count;
}

// Types
export interface Email {
  id: string;
  from: string;
  subject: string;
  body: string;
  received_at: string;
}
