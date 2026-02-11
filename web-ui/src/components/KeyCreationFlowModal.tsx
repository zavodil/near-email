'use client';

import { useState } from 'react';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes } from '@noble/ciphers/webcrypto';
import { sendTransaction, getOutlayerContractId, viewMethod } from '@/lib/near';

interface KeyCreationFlowModalProps {
  accountId: string;
  onComplete: (paymentKey: string) => void;
  onCancel: () => void;
}

type Step = 'intro' | 'generating' | 'registering' | 'funding' | 'complete' | 'error';

// Generate a random 32-byte key
function generateSecretKey(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// Encrypt with ChaCha20-Poly1305 using keystore pubkey (symmetric key)
// Format: nonce (12 bytes) || ciphertext + tag
function encryptWithPubkey(pubkeyHex: string, plaintext: string): Uint8Array {
  const key = hexToBytes(pubkeyHex);
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const nonce = randomBytes(12);
  const cipher = chacha20poly1305(key, nonce);
  const ciphertextWithTag = cipher.encrypt(plaintextBytes);
  const encrypted = new Uint8Array(12 + ciphertextWithTag.length);
  encrypted.set(nonce, 0);
  encrypted.set(ciphertextWithTag, 12);
  return encrypted;
}

// Fetch encryption pubkey from coordinator keystore
async function fetchEncryptionPubkey(owner: string, nonce: number): Promise<string> {
  const response = await fetch('/api/outlayer/secrets/pubkey', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      accessor: { type: 'System', PaymentKey: {} },
      owner,
      profile: nonce.toString(),
      secrets_json: '{}',
    }),
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to get encryption key: ${errorText}`);
  }
  const { pubkey } = await response.json();
  return pubkey;
}

// Convert NEAR to yoctoNEAR
function parseNearToYocto(near: string): string {
  const parsed = parseFloat(near);
  if (isNaN(parsed) || parsed <= 0) {
    throw new Error('Invalid NEAR amount');
  }
  // 1 NEAR = 10^24 yoctoNEAR
  const yocto = BigInt(Math.floor(parsed * 1e6)) * BigInt(1e18);
  return yocto.toString();
}

export default function KeyCreationFlowModal({
  accountId,
  onComplete,
  onCancel,
}: KeyCreationFlowModalProps) {
  const contractId = getOutlayerContractId();
  const [step, setStep] = useState<Step>('intro');
  const [nearAmount, setNearAmount] = useState<string>('1');
  const [secretKey, setSecretKey] = useState<string | null>(null);
  const [nonce, setNonce] = useState<number>(1);
  const [error, setError] = useState<string | null>(null);
  const [generatedPaymentKey, setGeneratedPaymentKey] = useState<string | null>(null);

  const handleStart = async () => {
    try {
      setError(null);
      setStep('generating');

      // Validate minimum amount (0.01 NEAR min deposit + 0.025 NEAR execution fees)
      const amountNum = parseFloat(nearAmount);
      if (isNaN(amountNum) || amountNum < 0.035) {
        throw new Error('Minimum deposit is 0.035 NEAR (includes 0.025 NEAR fee)');
      }

      // Step 1: Generate secret key
      const key = generateSecretKey();
      setSecretKey(key);

      // Query contract for next available nonce (must succeed before any transactions)
      let keyNonce: number;
      try {
        keyNonce = await viewMethod({ contractId, method: 'get_next_payment_key_nonce', args: { account_id: accountId } }) as number;
      } catch (err) {
        throw new Error('Failed to query payment key nonce from contract. Please try again.');
      }
      if (!keyNonce || keyNonce < 1) {
        throw new Error('Invalid nonce returned from contract');
      }
      setNonce(keyNonce);

      // Fetch encryption pubkey from coordinator keystore
      const pubkey = await fetchEncryptionPubkey(accountId, keyNonce);

      // Prepare secret data (same format as dashboard CreateKeyForm)
      const secretData = {
        key,
        project_ids: [] as string[],
        max_per_call: '0',
        initial_balance: '0',
      };
      const secretJson = JSON.stringify(secretData);

      // Encrypt with ChaCha20-Poly1305 using keystore pubkey
      const encryptedArray = encryptWithPubkey(pubkey, secretJson);
      const encryptedBase64 = btoa(String.fromCharCode(...Array.from(encryptedArray)));

      // Save to localStorage in case of page reload during transaction
      const storageKey = `payment_key_creation_${accountId}`;
      localStorage.setItem(storageKey, JSON.stringify({
        secretKey: key,
        nonce: keyNonce,
        step: 'store_secrets',
        nearAmount,
        timestamp: Date.now(),
      }));

      setStep('registering');

      // Step 2: Call store_secrets to register the payment key on contract
      // This creates the payment key entry with 0 balance
      const storeSecretsArgs = {
        accessor: { System: 'PaymentKey' },
        profile: keyNonce.toString(),
        encrypted_secrets_base64: encryptedBase64,
        access: 'AllowAll',
      };

      await sendTransaction({
        receiverId: contractId,
        actions: [{
          type: 'FunctionCall',
          params: {
            methodName: 'store_secrets',
            args: storeSecretsArgs,
            gas: '100000000000000', // 100 TGas
            deposit: '10000000000000000000000', // 0.01 NEAR for storage (excess refunded)
          },
        }],
      });

      // Update localStorage step
      localStorage.setItem(storageKey, JSON.stringify({
        secretKey: key,
        nonce: keyNonce,
        step: 'top_up',
        nearAmount,
        timestamp: Date.now(),
      }));

      setStep('funding');

      // Step 3: Call top_up_payment_key_with_near to add balance
      const yoctoNear = parseNearToYocto(nearAmount);
      const swapContractId = 'v1.publishintent.near';

      await sendTransaction({
        receiverId: contractId,
        actions: [{
          type: 'FunctionCall',
          params: {
            methodName: 'top_up_payment_key_with_near',
            args: { nonce: keyNonce, swap_contract_id: swapContractId },
            gas: '200000000000000', // 200 TGas (needs more for cross-contract calls)
            deposit: yoctoNear,
          },
        }],
      });

      // Success! Clean up localStorage
      localStorage.removeItem(storageKey);

      // Create the full payment key string
      const fullKey = `${accountId}:${keyNonce}:${key}`;
      setGeneratedPaymentKey(fullKey);
      setStep('complete');

    } catch (err) {
      console.error('Key creation failed:', err);
      setError((err as Error).message);
      setStep('error');
    }
  };

  const handleCopyKey = () => {
    if (generatedPaymentKey) {
      navigator.clipboard.writeText(generatedPaymentKey);
    }
  };

  const handleFinish = () => {
    if (generatedPaymentKey) {
      onComplete(generatedPaymentKey);
    }
  };

  // Intro screen - shows NEAR amount input
  if (step === 'intro') {
    return (
      <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
        <div className="bg-white rounded-xl shadow-xl p-6 max-w-md w-full">
          <h2 className="text-xl font-bold text-gray-900 mb-2">
            Create Payment Key
          </h2>
          <p className="text-sm text-gray-600 mb-4">
            Create a payment key to access near.email without wallet transactions.
            Your NEAR will be converted to USDC for API usage.
          </p>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Initial deposit (NEAR)
            </label>
            <input
              type="text"
              value={nearAmount}
              onChange={(e) => setNearAmount(e.target.value)}
              placeholder="1.0"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-gray-900 placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <p className="text-xs text-gray-500 mt-1">
              Minimum 0.035 NEAR (includes 0.025 NEAR fee). Additional ~0.01 NEAR for storage (excess refunded).
            </p>
          </div>

          <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
            <p className="text-sm text-blue-800">
              This will require 2 transactions:
            </p>
            <ol className="text-sm text-blue-700 mt-2 list-decimal list-inside">
              <li>Register payment key (~0.01 NEAR storage, excess refunded)</li>
              <li>Top up with NEAR (swapped to USDC)</li>
            </ol>
          </div>

          <div className="flex gap-3">
            <button
              onClick={onCancel}
              className="flex-1 bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-lg font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleStart}
              className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-colors"
            >
              Create Key
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Processing steps
  if (step === 'generating' || step === 'registering' || step === 'funding') {
    const stepMessages = {
      generating: 'Generating secure key...',
      registering: 'Registering on blockchain...',
      funding: 'Adding NEAR balance...',
    };

    return (
      <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
        <div className="bg-white rounded-xl shadow-xl p-6 max-w-md w-full text-center">
          <div className="inline-block w-12 h-12 border-4 border-gray-200 border-t-blue-500 rounded-full animate-spin mb-4"></div>
          <h2 className="text-xl font-bold text-gray-900 mb-2">
            {stepMessages[step]}
          </h2>
          <p className="text-sm text-gray-600">
            Please approve the transaction in your wallet.
          </p>

          <div className="mt-6 flex justify-center gap-2">
            {['generating', 'registering', 'funding'].map((s, i) => (
              <div
                key={s}
                className={`w-3 h-3 rounded-full ${
                  step === s
                    ? 'bg-blue-500'
                    : ['generating', 'registering', 'funding'].indexOf(step) > i
                    ? 'bg-green-500'
                    : 'bg-gray-300'
                }`}
              />
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Error state
  if (step === 'error') {
    return (
      <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
        <div className="bg-white rounded-xl shadow-xl p-6 max-w-md w-full">
          <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </div>
          <h2 className="text-xl font-bold text-gray-900 text-center mb-2">
            Something went wrong
          </h2>
          <p className="text-sm text-red-600 text-center mb-4">
            {error}
          </p>
          <div className="flex gap-3">
            <button
              onClick={onCancel}
              className="flex-1 bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-lg font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={() => setStep('intro')}
              className="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-colors"
            >
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Complete state
  if (step === 'complete' && generatedPaymentKey) {
    return (
      <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
        <div className="bg-white rounded-xl shadow-xl p-6 max-w-md w-full">
          <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 className="text-xl font-bold text-gray-900 text-center mb-2">
            Payment Key Created!
          </h2>
          <p className="text-sm text-gray-600 text-center mb-4">
            Save this key securely. You&apos;ll need it to access your email.
          </p>

          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 mb-4">
            <p className="text-xs text-yellow-800 font-medium mb-2">
              YOUR PAYMENT KEY (save now!)
            </p>
            <code className="text-xs text-gray-900 break-all block bg-white p-2 rounded border border-yellow-300">
              {generatedPaymentKey}
            </code>
            <button
              onClick={handleCopyKey}
              className="mt-2 w-full bg-yellow-100 hover:bg-yellow-200 text-yellow-800 px-3 py-1.5 rounded text-sm font-medium transition-colors"
            >
              Copy to Clipboard
            </button>
          </div>

          <p className="text-xs text-gray-500 text-center mb-4">
            This key will NOT be shown again. Store it securely before continuing.
          </p>

          <button
            onClick={handleFinish}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition-colors"
          >
            Continue to Email
          </button>
        </div>
      </div>
    );
  }

  return null;
}
