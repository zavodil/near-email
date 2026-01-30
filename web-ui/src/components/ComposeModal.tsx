import { useState, useRef, useEffect } from 'react';
import type { Attachment } from '@/lib/near';
import { getMaxSendFileSize, getMaxSendTotalSize, isPaymentKeyMode } from '@/lib/near';

// Network configuration
const NETWORK_ID = process.env.NEXT_PUBLIC_NETWORK_ID || 'mainnet';
const ACCOUNT_SUFFIX = NETWORK_ID === 'testnet' ? '.testnet' : '.near';
const FASTNEAR_RPC_URL = NETWORK_ID === 'testnet'
  ? 'https://rpc.testnet.fastnear.com'
  : 'https://free.rpc.fastnear.com';
const EMAIL_DOMAIN = 'near.email';

// Validation status for the To field
type ToStatus = 'idle' | 'checking' | 'valid' | 'invalid';

// Check if string looks like an email
function isEmailFormat(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

// Check if string looks like a NEAR account (without subaccount)
// Valid: alice.near, bob.testnet
// Invalid: sub.alice.near (subaccount)
function isNearAccountFormat(value: string): boolean {
  const suffix = ACCOUNT_SUFFIX;
  if (!value.endsWith(suffix)) return false;

  const nameWithoutSuffix = value.slice(0, -suffix.length);
  // Should not contain dots (would be a subaccount)
  if (nameWithoutSuffix.includes('.')) return false;
  // Should be valid NEAR account name (lowercase alphanumeric, -, _)
  return /^[a-z0-9_-]+$/.test(nameWithoutSuffix);
}

// Check if string looks like an account with unrecognized suffix (like .something)
function hasUnrecognizedSuffix(value: string): boolean {
  // Must contain a dot but not end with recognized suffixes
  if (!value.includes('.')) return false;
  if (value.endsWith('.near') || value.endsWith('.testnet')) return false;
  // Check if it looks like account.suffix format (no @ sign, alphanumeric with dots)
  return /^[a-z0-9_-]+\.[a-z0-9_-]+$/i.test(value);
}

// Check if NEAR account exists via FastNEAR RPC (CORS-friendly)
async function checkNearAccountExists(accountId: string): Promise<boolean> {
  try {
    const response = await fetch(FASTNEAR_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: '1',
        method: 'query',
        params: {
          request_type: 'view_account',
          finality: 'final',
          account_id: accountId,
        },
      }),
    });

    const data = await response.json();
    // If there's no error and result exists, account exists
    return !data.error && data.result;
  } catch {
    return false;
  }
}

interface ComposeModalProps {
  fromAddress: string;
  onClose: () => void;
  onSent: (to: string, subject: string, body: string, attachments?: Attachment[]) => Promise<void>;
  onSuccess?: () => void;
  onShowLimits?: () => void;
  // Optional initial values for reply
  initialTo?: string;
  initialSubject?: string;
  initialBody?: string;
}

export default function ComposeModal({
  fromAddress,
  onClose,
  onSent,
  onSuccess,
  onShowLimits,
  initialTo = '',
  initialSubject = '',
  initialBody = '',
}: ComposeModalProps) {
  const [to, setTo] = useState(initialTo);
  const [subject, setSubject] = useState(initialSubject);
  const [body, setBody] = useState(initialBody);
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // To field validation state
  const [toStatus, setToStatus] = useState<ToStatus>('idle');
  const [toError, setToError] = useState<string | null>(null);

  // Validate To field when it changes
  useEffect(() => {
    const value = to.trim().toLowerCase();

    if (!value) {
      setToStatus('idle');
      setToError(null);
      return;
    }

    // Check if it's an email format
    if (isEmailFormat(value)) {
      setToStatus('valid');
      setToError(null);
      return;
    }

    // Check if it looks like a subaccount (invalid)
    if (value.endsWith(ACCOUNT_SUFFIX)) {
      const nameWithoutSuffix = value.slice(0, -ACCOUNT_SUFFIX.length);
      if (nameWithoutSuffix.includes('.')) {
        setToStatus('invalid');
        setToError('Subaccounts not supported. Use main account (e.g., alice' + ACCOUNT_SUFFIX + ')');
        return;
      }
    }

    // If looks like NEAR account format, we'll validate on blur
    if (isNearAccountFormat(value)) {
      setToStatus('idle');
      setToError(null);
      return;
    }

    // Check for unrecognized suffix (e.g., alice.something instead of alice.near)
    if (hasUnrecognizedSuffix(value)) {
      setToStatus('invalid');
      setToError(`Unknown suffix. Use ${ACCOUNT_SUFFIX} or full email address`);
      return;
    }

    // Unknown format - show hint
    setToStatus('idle');
    setToError(null);
  }, [to]);

  // Validate NEAR account on blur
  async function handleToBlur() {
    const value = to.trim().toLowerCase();

    if (!value || isEmailFormat(value)) return;

    if (isNearAccountFormat(value)) {
      setToStatus('checking');
      setToError(null);

      const exists = await checkNearAccountExists(value);

      if (exists) {
        // Convert NEAR account to email format
        const nameWithoutSuffix = value.slice(0, -ACCOUNT_SUFFIX.length);
        const emailAddress = `${nameWithoutSuffix}@${EMAIL_DOMAIN}`;
        setTo(emailAddress);
        setToStatus('valid');
        setToError(null);
      } else {
        setToStatus('invalid');
        setToError(`Account "${value}" not found on NEAR ${NETWORK_ID}`);
      }
    }
  }

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function getTotalSize(): number {
    return attachments.reduce((sum, att) => sum + att.size, 0);
  }

  async function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const files = e.target.files;
    if (!files) return;

    const maxFileSize = getMaxSendFileSize();
    const maxTotalSize = getMaxSendTotalSize();
    const modeHint = isPaymentKeyMode() ? '' : ' Use Payment Key mode for larger attachments.';

    for (const file of Array.from(files)) {
      if (file.size > maxFileSize) {
        setError(`File "${file.name}" is too large (${formatSize(file.size)}). Maximum: ${formatSize(maxFileSize)} per file.${modeHint}`);
        continue;
      }

      if (getTotalSize() + file.size > maxTotalSize) {
        setError(`Total size (${formatSize(getTotalSize() + file.size)}) exceeds limit (${formatSize(maxTotalSize)}).${modeHint}`);
        break;
      }

      // Read file as base64
      const reader = new FileReader();
      reader.onload = () => {
        const base64 = (reader.result as string).split(',')[1]; // Remove data:...;base64, prefix
        const newAttachment: Attachment = {
          filename: file.name,
          content_type: file.type || 'application/octet-stream',
          data: base64,
          size: file.size,
        };
        setAttachments(prev => [...prev, newAttachment]);
      };
      reader.readAsDataURL(file);
    }

    // Reset input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  }

  function removeAttachment(index: number) {
    setAttachments(prev => prev.filter((_, i) => i !== index));
  }

  async function handleSend() {
    if (!to.trim()) {
      setError('Please enter a recipient');
      return;
    }

    setSending(true);
    setError(null);

    try {
      await onSent(to, subject, body, attachments.length > 0 ? attachments : undefined);
      onSuccess?.();
      onClose();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSending(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className="flex justify-between items-center px-4 py-3 border-b border-gray-100">
          <h2 className="text-base font-semibold text-gray-900">New Message</h2>
          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-md transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Form */}
        <div className="px-4 py-3 space-y-3 overflow-y-auto flex-1">
          {error && (
            <div className="bg-red-50 text-red-700 px-3 py-2 rounded-lg text-sm border border-red-100">
              {error}
            </div>
          )}

          <div className="flex items-center gap-2 py-1.5 border-b border-gray-100">
            <label className="text-sm text-gray-400 w-14">From</label>
            <span className="text-sm text-gray-600">{fromAddress}</span>
          </div>

          <div className="space-y-1">
            <div className="flex items-center gap-2 py-1.5 border-b border-gray-100">
              <label className="text-sm text-gray-400 w-14">To</label>
              <input
                type="text"
                value={to}
                onChange={(e) => setTo(e.target.value)}
                onBlur={handleToBlur}
                placeholder={`email or NEAR account (e.g., alice${ACCOUNT_SUFFIX})`}
                className={`flex-1 text-sm text-gray-900 placeholder-gray-300 focus:outline-none ${
                  toStatus === 'invalid' ? 'text-red-600' : ''
                }`}
              />
              {/* Validation indicator */}
              {toStatus === 'checking' && (
                <svg className="w-4 h-4 text-gray-400 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
              )}
              {toStatus === 'valid' && (
                <svg className="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              )}
              {toStatus === 'invalid' && (
                <svg className="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              )}
            </div>
            {/* Error message */}
            {toError && (
              <p className="text-xs text-red-500 pl-16">{toError}</p>
            )}
            {/* Hint (show only when idle and empty) */}
            {toStatus === 'idle' && !to.trim() && (
              <p className="text-xs text-gray-400 pl-16">
                Enter email address or NEAR account (subaccounts not supported)
              </p>
            )}
          </div>

          <div className="flex items-center gap-2 py-1.5 border-b border-gray-100">
            <label className="text-sm text-gray-400 w-14">Subject</label>
            <input
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="Subject"
              className="flex-1 text-sm text-gray-900 placeholder-gray-300 focus:outline-none"
            />
          </div>

          <div className="flex-1">
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={6}
              placeholder="Write your message..."
              className="w-full text-sm text-gray-700 placeholder-gray-300 focus:outline-none resize-none"
            />
          </div>

          {/* Attachments */}
          {attachments.length > 0 && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs text-gray-400">
                  {attachments.length} {attachments.length === 1 ? 'file' : 'files'}
                </span>
                <span className="text-xs text-gray-400">
                  {formatSize(getTotalSize())} / {formatSize(getMaxSendTotalSize())}
                </span>
              </div>
              {/* Progress bar */}
              <div className="w-full bg-gray-200 rounded-full h-1.5">
                <div
                  className={`h-1.5 rounded-full transition-all ${
                    getTotalSize() > getMaxSendTotalSize() * 0.9 ? 'bg-red-500' :
                    getTotalSize() > getMaxSendTotalSize() * 0.7 ? 'bg-yellow-500' : 'bg-blue-500'
                  }`}
                  style={{ width: `${Math.min(100, (getTotalSize() / getMaxSendTotalSize()) * 100)}%` }}
                />
              </div>
              <div className="flex flex-wrap gap-1.5">
                {attachments.map((att, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-1.5 px-2 py-1 bg-gray-50 rounded-md text-xs border border-gray-200"
                  >
                    <svg className="w-3.5 h-3.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
                    </svg>
                    <span className="text-gray-700 max-w-[120px] truncate">{att.filename}</span>
                    <span className="text-gray-400">({formatSize(att.size)})</span>
                    <button
                      onClick={() => removeAttachment(idx)}
                      className="text-gray-400 hover:text-red-500 transition-colors"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                ))}
              </div>
              {/* Limits hint */}
              {onShowLimits && (
                <button
                  onClick={onShowLimits}
                  className="text-xs text-blue-500 hover:underline"
                >
                  View size limits
                </button>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100 bg-gray-50/50 rounded-b-2xl">
          <div className="flex items-center gap-1">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileSelect}
              multiple
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
              title="Attach file"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
              </svg>
            </button>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3 py-1.5 text-sm text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSend}
              disabled={sending}
              className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 shadow-sm"
            >
              {sending ? (
                <>
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Sending...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                  </svg>
                  Send
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
