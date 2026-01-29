import { useState, useEffect } from 'react';
import {
  getMyInvites,
  generateInviteCode,
  sendInviteEmail,
  type MyInvitesResult,
  type InviteRecord,
} from '@/lib/near';

interface InvitesModalProps {
  accountId: string;
  isOpen: boolean;
  onClose: () => void;
  walletConnected: boolean;
  onConnectWallet: () => void;
  // For showing warning when wallet account differs from payment key owner
  walletAccountId: string | null;
  paymentKeyOwner: string | null;
}

type Tab = 'status' | 'send' | 'code';

export default function InvitesModal({ accountId, isOpen, onClose, walletConnected, onConnectWallet, walletAccountId, paymentKeyOwner }: InvitesModalProps) {
  // Show warning if user is in payment key mode but wallet is different account
  const showAccountMismatchWarning = walletConnected && paymentKeyOwner && walletAccountId && paymentKeyOwner !== walletAccountId;
  const [tab, setTab] = useState<Tab>('status');
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<MyInvitesResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Send invite state
  const [recipientEmail, setRecipientEmail] = useState('');
  const [sendLoading, setSendLoading] = useState(false);
  const [sendResult, setSendResult] = useState<{ success: boolean; message: string } | null>(null);

  // Generate code state
  const [generatedCode, setGeneratedCode] = useState<string | null>(null);
  const [generateLoading, setGenerateLoading] = useState(false);
  const [codeExpiresAt, setCodeExpiresAt] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (isOpen && accountId && walletConnected) {
      loadInvites();
    }
  }, [isOpen, accountId, walletConnected]);

  async function loadInvites() {
    setLoading(true);
    setError(null);
    try {
      const result = await getMyInvites(accountId);
      setData(result);
    } catch (err: any) {
      setError(err.message || 'Failed to load invites');
    } finally {
      setLoading(false);
    }
  }

  async function handleSendInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!recipientEmail.trim()) return;

    setSendLoading(true);
    setSendResult(null);
    try {
      const result = await sendInviteEmail(accountId, recipientEmail.trim());
      if (result.success) {
        setSendResult({ success: true, message: `Invite sent to ${recipientEmail}` });
        setRecipientEmail('');
        loadInvites(); // Refresh data
      } else {
        setSendResult({ success: false, message: result.error || 'Failed to send invite' });
      }
    } catch (err: any) {
      setSendResult({ success: false, message: err.message || 'Failed to send invite' });
    } finally {
      setSendLoading(false);
    }
  }

  async function handleGenerateCode() {
    setGenerateLoading(true);
    setGeneratedCode(null);
    setCodeExpiresAt(null);
    try {
      const result = await generateInviteCode(accountId);
      if (result.success && result.code) {
        setGeneratedCode(result.code);
        setCodeExpiresAt(result.expires_at || null);
        loadInvites(); // Refresh data
      } else {
        setError(result.error || 'Failed to generate code');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to generate code');
    } finally {
      setGenerateLoading(false);
    }
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function copyInviteLink() {
    if (!generatedCode) return;
    const link = `https://near.email?invite=${generatedCode}`;
    copyToClipboard(link);
  }

  function formatDate(dateStr: string): string {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  function getStatusBadge(status: string) {
    switch (status) {
      case 'used':
        return <span className="px-2 py-0.5 text-xs font-medium bg-green-100 text-green-700 rounded-full">Used</span>;
      case 'expired':
        return <span className="px-2 py-0.5 text-xs font-medium bg-gray-100 text-gray-500 rounded-full">Expired</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-medium bg-blue-100 text-blue-700 rounded-full">Pending</span>;
    }
  }

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-xl max-w-lg w-full max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold text-gray-900">Invites</h2>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Stats bar */}
        {walletConnected && data && (
          <div className="bg-gradient-to-r from-purple-50 to-blue-50 px-4 py-3 border-b">
            <div className="flex items-center justify-center gap-6">
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-600">{data.remaining_invites}</div>
                <div className="text-xs text-gray-500">remaining</div>
              </div>
              <div className="h-8 w-px bg-gray-200"></div>
              <div className="text-center">
                <div className="text-2xl font-bold text-gray-600">{data.used_invites}</div>
                <div className="text-xs text-gray-500">sent</div>
              </div>
              <div className="h-8 w-px bg-gray-200"></div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">
                  {data.invites.filter(i => i.status === 'used').length}
                </div>
                <div className="text-xs text-gray-500">joined</div>
              </div>
            </div>
          </div>
        )}

        {/* Account mismatch warning */}
        {showAccountMismatchWarning && (
          <div className="bg-amber-50 border-b border-amber-100 px-4 py-2">
            <div className="flex items-start gap-2">
              <svg className="w-4 h-4 text-amber-500 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <p className="text-xs text-amber-700">
                You're managing invites for <span className="font-medium">{walletAccountId}</span>, not your payment key account <span className="font-medium">{paymentKeyOwner}</span>.
              </p>
            </div>
          </div>
        )}

        {/* Tabs */}
        {walletConnected && (
          <div className="flex border-b">
            <button
              onClick={() => setTab('status')}
              className={`flex-1 py-2.5 text-sm font-medium transition-colors ${
                tab === 'status'
                  ? 'text-purple-600 border-b-2 border-purple-600 bg-purple-50/50'
                  : 'text-gray-500 hover:bg-gray-50'
              }`}
            >
              My Invites
            </button>
            <button
              onClick={() => setTab('send')}
              className={`flex-1 py-2.5 text-sm font-medium transition-colors ${
                tab === 'send'
                  ? 'text-purple-600 border-b-2 border-purple-600 bg-purple-50/50'
                  : 'text-gray-500 hover:bg-gray-50'
              }`}
            >
              Send via Email
            </button>
            <button
              onClick={() => setTab('code')}
              className={`flex-1 py-2.5 text-sm font-medium transition-colors ${
                tab === 'code'
                  ? 'text-purple-600 border-b-2 border-purple-600 bg-purple-50/50'
                  : 'text-gray-500 hover:bg-gray-50'
              }`}
            >
              Get Code
            </button>
          </div>
        )}

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {!walletConnected ? (
            <div className="text-center py-8">
              <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Wallet Required</h3>
              <p className="text-sm text-gray-500 mb-6">
                To manage invites, you need to connect your NEAR wallet.<br />
                This is required for signature verification.
              </p>
              <button
                onClick={onConnectWallet}
                className="px-6 py-2.5 bg-purple-600 text-white rounded-xl font-medium hover:bg-purple-700 transition-colors"
              >
                Connect Wallet
              </button>
            </div>
          ) : loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-8 h-8 border-3 border-gray-200 border-t-purple-500 rounded-full animate-spin"></div>
            </div>
          ) : error ? (
            <div className="text-center py-8">
              <p className="text-red-600 text-sm">{error}</p>
              <button
                onClick={loadInvites}
                className="mt-4 text-purple-600 hover:text-purple-700 text-sm font-medium"
              >
                Try again
              </button>
            </div>
          ) : (
            <>
              {/* Status Tab */}
              {tab === 'status' && data && (
                <div className="space-y-3">
                  {data.invites.length === 0 ? (
                    <div className="text-center py-8 text-gray-500">
                      <p className="text-sm">No invites sent yet</p>
                      <p className="text-xs mt-1">Use the other tabs to invite friends</p>
                    </div>
                  ) : (
                    data.invites.map((invite: InviteRecord) => (
                      <div
                        key={invite.id}
                        className="bg-gray-50 rounded-lg p-3 flex items-center justify-between"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <code className="text-sm font-mono bg-white px-2 py-0.5 rounded border">
                              {invite.code}
                            </code>
                            {getStatusBadge(invite.status)}
                          </div>
                          <div className="text-xs text-gray-500 mt-1">
                            {invite.recipient_email ? (
                              <span>Sent to {invite.recipient_email}</span>
                            ) : (
                              <span>Code generated</span>
                            )}
                            {' · '}
                            {invite.status === 'used' && invite.used_by ? (
                              <span className="text-green-600">Joined as {invite.used_by}</span>
                            ) : invite.status === 'expired' ? (
                              <span>Expired</span>
                            ) : (
                              <span>Expires {formatDate(invite.expires_at)}</span>
                            )}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Send via Email Tab */}
              {tab === 'send' && (
                <form onSubmit={handleSendInvite} className="space-y-4">
                  <p className="text-sm text-gray-500">
                    Enter your friend's email and we'll send them an invite on your behalf.
                  </p>

                  {sendResult && (
                    <div
                      className={`px-4 py-3 rounded-lg text-sm ${
                        sendResult.success
                          ? 'bg-green-50 text-green-700 border border-green-100'
                          : 'bg-red-50 text-red-700 border border-red-100'
                      }`}
                    >
                      {sendResult.message}
                    </div>
                  )}

                  <input
                    type="email"
                    value={recipientEmail}
                    onChange={(e) => setRecipientEmail(e.target.value)}
                    placeholder="friend@example.com"
                    className="w-full px-4 py-3 border border-gray-300 rounded-xl focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                    disabled={data?.remaining_invites === 0}
                  />

                  <button
                    type="submit"
                    disabled={sendLoading || !recipientEmail.trim() || data?.remaining_invites === 0}
                    className="w-full px-4 py-3 bg-purple-600 text-white rounded-xl font-medium hover:bg-purple-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  >
                    {sendLoading ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                        Sending...
                      </>
                    ) : (
                      <>
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                        </svg>
                        Send Invite
                      </>
                    )}
                  </button>

                  {data?.remaining_invites === 0 && (
                    <p className="text-sm text-red-600 text-center">
                      You've used all your invites
                    </p>
                  )}
                </form>
              )}

              {/* Get Code Tab */}
              {tab === 'code' && (
                <div className="space-y-4">
                  <p className="text-sm text-gray-500">
                    Generate a code to share on Twitter, Telegram, or anywhere else.
                  </p>

                  {generatedCode ? (
                    <div className="bg-gradient-to-r from-purple-50 to-blue-50 rounded-xl p-6 text-center">
                      <p className="text-xs text-gray-500 mb-2">Your invite code</p>
                      <code className="text-3xl font-mono font-bold tracking-widest text-purple-700">
                        {generatedCode}
                      </code>
                      {codeExpiresAt && (
                        <p className="text-xs text-gray-500 mt-2">
                          Expires {formatDate(codeExpiresAt)}
                        </p>
                      )}

                      <div className="flex gap-2 mt-4">
                        <button
                          onClick={() => copyToClipboard(generatedCode)}
                          className="flex-1 px-4 py-2 bg-white border border-gray-200 rounded-lg text-sm font-medium hover:bg-gray-50 transition-colors flex items-center justify-center gap-2"
                        >
                          {copied ? (
                            <>
                              <svg className="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                              </svg>
                              Copied!
                            </>
                          ) : (
                            <>
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                              </svg>
                              Copy Code
                            </>
                          )}
                        </button>
                        <button
                          onClick={copyInviteLink}
                          className="flex-1 px-4 py-2 bg-purple-600 text-white rounded-lg text-sm font-medium hover:bg-purple-700 transition-colors flex items-center justify-center gap-2"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                          </svg>
                          Copy Link
                        </button>
                      </div>

                      <button
                        onClick={() => {
                          setGeneratedCode(null);
                          setCodeExpiresAt(null);
                        }}
                        className="mt-4 text-sm text-gray-500 hover:text-gray-700"
                      >
                        Generate another code
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={handleGenerateCode}
                      disabled={generateLoading || data?.remaining_invites === 0}
                      className="w-full px-4 py-4 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-xl font-medium hover:from-purple-700 hover:to-blue-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                    >
                      {generateLoading ? (
                        <>
                          <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                          Generating...
                        </>
                      ) : (
                        <>
                          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                          </svg>
                          Generate Invite Code
                        </>
                      )}
                    </button>
                  )}

                  {data?.remaining_invites === 0 && !generatedCode && (
                    <p className="text-sm text-red-600 text-center">
                      You've used all your invites
                    </p>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
