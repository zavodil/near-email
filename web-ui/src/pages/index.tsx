import { useState, useEffect } from 'react';
import type { AccountState } from '@near-wallet-selector/core';
import {
  showModal,
  signOut,
  getEmails,
  sendEmail,
  deleteEmail,
  type Email,
  type SentEmail,
  type GetEmailsResult,
  type Attachment,
} from '@/lib/near';
import EmailList from '@/components/EmailList';
import SentEmailList from '@/components/SentEmailList';
import EmailView from '@/components/EmailView';
import SentEmailView from '@/components/SentEmailView';
import ComposeModal from '@/components/ComposeModal';
import Toast, { type ToastType } from '@/components/Toast';

interface HomeProps {
  accounts: AccountState[];
  loading: boolean;
}

type Folder = 'inbox' | 'sent';

export default function Home({ accounts, loading }: HomeProps) {
  const [emails, setEmails] = useState<Email[]>([]);
  const [sentEmails, setSentEmails] = useState<SentEmail[]>([]);
  const [selectedEmail, setSelectedEmail] = useState<Email | null>(null);
  const [selectedSentEmail, setSelectedSentEmail] = useState<SentEmail | null>(null);
  const [loadingEmails, setLoadingEmails] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [showCompose, setShowCompose] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasCheckedMail, setHasCheckedMail] = useState(false);
  const [showAccountMenu, setShowAccountMenu] = useState(false);
  const [inboxNextOffset, setInboxNextOffset] = useState<number | null>(null);
  const [sentNextOffset, setSentNextOffset] = useState<number | null>(null);
  const [currentFolder, setCurrentFolder] = useState<Folder>('inbox');
  // Reply state
  const [replyTo, setReplyTo] = useState('');
  const [replySubject, setReplySubject] = useState('');
  const [replyBody, setReplyBody] = useState('');
  // Toast state
  const [toast, setToast] = useState<{ message: string; type: ToastType } | null>(null);

  function showToast(message: string, type: ToastType = 'success') {
    setToast({ message, type });
  }

  function pluralize(count: number, singular: string, plural: string) {
    return count === 1 ? singular : plural;
  }

  const isConnected = accounts.length > 0;
  const accountId = isConnected ? accounts[0].accountId : null;
  // Handle both .near and .testnet suffixes
  const emailAddress = accountId
    ? `${accountId.replace('.near', '').replace('.testnet', '')}@near.email`
    : null;

  // Update state from combined result
  function updateFromResult(result: GetEmailsResult | { inbox: Email[]; sent: SentEmail[] }) {
    setEmails(result.inbox);
    setSentEmails(result.sent);
    if ('inboxNextOffset' in result) {
      setInboxNextOffset(result.inboxNextOffset);
      setSentNextOffset(result.sentNextOffset);
    }
  }

  async function loadEmails() {
    setLoadingEmails(true);
    setError(null);
    try {
      const result = await getEmails(0, 0);
      updateFromResult(result);
      setHasCheckedMail(true);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoadingEmails(false);
    }
  }

  async function loadMoreInbox() {
    if (!inboxNextOffset) return;
    setLoadingMore(true);
    setError(null);
    try {
      const result = await getEmails(inboxNextOffset, 0);
      // Append new inbox emails to existing
      setEmails(prev => [...prev, ...result.inbox]);
      setSentEmails(result.sent);
      setInboxNextOffset(result.inboxNextOffset);
      setSentNextOffset(result.sentNextOffset);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoadingMore(false);
    }
  }

  async function loadMoreSent() {
    if (!sentNextOffset) return;
    setLoadingMore(true);
    setError(null);
    try {
      const result = await getEmails(0, sentNextOffset);
      // Keep current inbox, append new sent emails
      setEmails(result.inbox);
      setSentEmails(prev => [...prev, ...result.sent]);
      setInboxNextOffset(result.inboxNextOffset);
      setSentNextOffset(result.sentNextOffset);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoadingMore(false);
    }
  }

  function handleFolderChange(folder: Folder) {
    setCurrentFolder(folder);
    setSelectedEmail(null);
    setSelectedSentEmail(null);
  }

  function handleConnect() {
    showModal();
  }

  async function handleDisconnect() {
    await signOut();
    setEmails([]);
    setSentEmails([]);
    setSelectedEmail(null);
    setSelectedSentEmail(null);
    setHasCheckedMail(false);
    setInboxNextOffset(null);
    setSentNextOffset(null);
  }

  async function handleDelete(emailId: string) {
    try {
      const result = await deleteEmail(emailId);
      if (result.deleted) {
        // Update state from fresh data returned by delete
        updateFromResult(result);
        setSelectedEmail(null);
      }
    } catch (err: any) {
      setError(err.message);
    }
  }

  function handleReply(to: string, subject: string, body: string) {
    setReplyTo(to);
    setReplySubject(subject);
    setReplyBody(body);
    setShowCompose(true);
  }

  function handleOpenCompose() {
    // Reset reply state for new compose
    setReplyTo('');
    setReplySubject('');
    setReplyBody('');
    setShowCompose(true);
  }

  async function handleSend(to: string, subject: string, body: string, attachments?: Attachment[]): Promise<void> {
    const result = await sendEmail(to, subject, body, attachments);
    // Update state from fresh data returned by send
    updateFromResult(result);
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100">
        <div className="text-center">
          <div className="inline-block w-8 h-8 border-3 border-gray-200 border-t-blue-500 rounded-full animate-spin mb-4"></div>
          <p className="text-gray-500">Loading...</p>
        </div>
      </div>
    );
  }

  // Check mail screen - connected but hasn't checked yet
  if (isConnected && !hasCheckedMail) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-gradient-to-br from-gray-50 to-gray-100">
        <h1 className="text-3xl font-bold text-gray-900 mb-6">near.email</h1>

        <div className="bg-white rounded-2xl shadow-xl border border-gray-100 p-6 max-w-sm w-full text-center">
          <div className="w-14 h-14 bg-gradient-to-br from-blue-400 to-blue-600 rounded-full flex items-center justify-center text-white text-xl font-bold mx-auto mb-4">
            {accountId?.charAt(0).toUpperCase()}
          </div>
          <p className="text-sm text-gray-500 mb-1">Connected as</p>
          <p className="font-semibold text-gray-900 mb-1">{accountId}</p>
          <p className="text-sm text-gray-400 mb-6">{emailAddress}</p>

          {error && (
            <div className="bg-red-50 text-red-700 px-3 py-2 rounded-lg text-sm mb-4 border border-red-100">
              {error}
            </div>
          )}

          <button
            onClick={loadEmails}
            disabled={loadingEmails}
            className="w-full bg-blue-600 text-white py-2.5 px-6 rounded-xl font-medium hover:bg-blue-700 transition-colors disabled:opacity-50 shadow-sm flex items-center justify-center gap-2"
          >
            {loadingEmails ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                Loading...
              </>
            ) : (
              <>
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
                Check Mail
              </>
            )}
          </button>

          <button
            onClick={handleDisconnect}
            className="mt-4 text-sm text-gray-400 hover:text-red-600 transition-colors"
          >
            Sign out
          </button>
        </div>
      </div>
    );
  }

  // Landing page for non-connected users
  if (!isConnected) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-gradient-to-br from-gray-50 to-gray-100">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-3">near.email</h1>
          <p className="text-lg text-gray-500 max-w-sm">
            Blockchain-native email for NEAR accounts
          </p>
        </div>

        <div className="bg-white rounded-2xl shadow-xl border border-gray-100 p-6 max-w-sm w-full">
          <div className="space-y-3 mb-6">
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 bg-emerald-100 rounded-lg flex items-center justify-center flex-shrink-0">
                <svg className="w-4 h-4 text-emerald-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-800">Your NEAR = Your email</p>
                <p className="text-xs text-gray-400">alice.near = alice@near.email</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0">
                <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-800">End-to-end encrypted</p>
                <p className="text-xs text-gray-400">Only you can read your emails</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 bg-purple-100 rounded-lg flex items-center justify-center flex-shrink-0">
                <svg className="w-4 h-4 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-800">Instant setup</p>
                <p className="text-xs text-gray-400">Just connect your wallet</p>
              </div>
            </div>
          </div>

          <button
            onClick={handleConnect}
            className="w-full bg-gray-900 text-white py-2.5 px-6 rounded-xl font-medium hover:bg-gray-800 transition-colors shadow-sm flex items-center justify-center gap-2"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
              <path d="M20.38 8.53L12 4.26 3.62 8.53v6.94L12 19.74l8.38-4.27V8.53zm-8.33 8.57l-6.45-3.28V9.46L12 5.74l6.4 3.72v4.36l-6.35 3.28z"/>
            </svg>
            Connect NEAR Wallet
          </button>
        </div>

        <p className="text-xs text-gray-400 mt-6">
          Powered by NEAR blockchain
        </p>
      </div>
    );
  }

  // Email interface for connected users
  return (
    <div className="min-h-screen flex flex-col bg-gray-50">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm border-b border-gray-100 px-4 py-3 flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold text-gray-900">near.email</h1>
          <span className="text-xs text-gray-400 hidden sm:inline">{emailAddress}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleOpenCompose}
            className="flex items-center gap-1.5 bg-blue-600 text-white px-3 py-1.5 text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors shadow-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Compose
          </button>
          {/* Account dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowAccountMenu(!showAccountMenu)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <div className="w-6 h-6 bg-gradient-to-br from-blue-400 to-blue-600 rounded-full flex items-center justify-center text-white text-xs font-medium">
                {accountId?.charAt(0).toUpperCase()}
              </div>
              <span className="hidden sm:inline max-w-[120px] truncate">{accountId}</span>
              <svg className="w-3.5 h-3.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {showAccountMenu && (
              <div className="absolute right-0 mt-1 w-48 bg-white rounded-lg shadow-lg border border-gray-100 py-1 z-50">
                <div className="px-3 py-2 border-b border-gray-100">
                  <p className="text-xs text-gray-400">Signed in as</p>
                  <p className="text-sm font-medium text-gray-700 truncate">{accountId}</p>
                </div>
                <button
                  onClick={() => {
                    handleDisconnect();
                    setShowAccountMenu(false);
                  }}
                  className="w-full text-left px-3 py-2 text-sm text-red-600 hover:bg-red-50 transition-colors"
                >
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Error banner */}
      {error && (
        <div className="bg-red-50 border-b border-red-100 px-4 py-2 flex items-center justify-between text-sm">
          <span className="text-red-700">{error}</span>
          <button onClick={() => setError(null)} className="text-red-500 hover:text-red-700 p-1">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Main content */}
      <main className="flex-1 flex overflow-hidden" onClick={() => showAccountMenu && setShowAccountMenu(false)}>
        {/* Email list */}
        <div className="w-80 flex-shrink-0 border-r border-gray-200 bg-white overflow-y-auto flex flex-col">
          {/* Folder tabs */}
          <div className="flex border-b">
            <button
              onClick={() => handleFolderChange('inbox')}
              className={`flex-1 py-2.5 text-center text-sm font-medium transition-colors ${
                currentFolder === 'inbox'
                  ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50/50'
                  : 'text-gray-500 hover:bg-gray-50'
              }`}
            >
              Inbox ({emails.length}{inboxNextOffset ? '+' : ''} {pluralize(emails.length, 'email', 'emails')})
            </button>
            <button
              onClick={() => handleFolderChange('sent')}
              className={`flex-1 py-2.5 text-center text-sm font-medium transition-colors ${
                currentFolder === 'sent'
                  ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50/50'
                  : 'text-gray-500 hover:bg-gray-50'
              }`}
            >
              Sent ({sentEmails.length}{sentNextOffset ? '+' : ''} {pluralize(sentEmails.length, 'email', 'emails')})
            </button>
          </div>

          {/* Refresh button */}
          <div className="px-3 py-2 border-b bg-gray-50/50 flex items-center justify-end">
            <button
              onClick={loadEmails}
              disabled={loadingEmails}
              className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-md transition-colors disabled:opacity-50"
              title="Refresh"
            >
              <svg className={`w-4 h-4 ${loadingEmails ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
          </div>

          {/* Email list content */}
          <div className="flex-1 overflow-y-auto">
            {currentFolder === 'inbox' ? (
              <>
                <EmailList
                  emails={emails}
                  selectedId={selectedEmail?.id}
                  onSelect={setSelectedEmail}
                  loading={loadingEmails}
                />
                {inboxNextOffset && !loadingEmails && (
                  <div className="p-4 border-t">
                    <button
                      onClick={loadMoreInbox}
                      disabled={loadingMore}
                      className="w-full py-2 text-blue-600 hover:text-blue-700 transition-colors disabled:opacity-50"
                    >
                      {loadingMore ? 'Loading...' : 'Load more emails'}
                    </button>
                  </div>
                )}
              </>
            ) : (
              <>
                <SentEmailList
                  emails={sentEmails}
                  selectedId={selectedSentEmail?.id}
                  onSelect={setSelectedSentEmail}
                  loading={loadingEmails}
                />
                {sentNextOffset && !loadingEmails && (
                  <div className="p-4 border-t">
                    <button
                      onClick={loadMoreSent}
                      disabled={loadingMore}
                      className="w-full py-2 text-blue-600 hover:text-blue-700 transition-colors disabled:opacity-50"
                    >
                      {loadingMore ? 'Loading...' : 'Load more emails'}
                    </button>
                  </div>
                )}
              </>
            )}
          </div>
        </div>

        {/* Email view */}
        <div className="flex-1 bg-gray-50 overflow-y-auto">
          {currentFolder === 'inbox' ? (
            selectedEmail ? (
              <EmailView
                email={selectedEmail}
                onDelete={() => handleDelete(selectedEmail.id)}
                onReply={handleReply}
              />
            ) : (
              <div className="flex items-center justify-center h-full text-gray-500">
                Select an email to read
              </div>
            )
          ) : (
            selectedSentEmail ? (
              <SentEmailView email={selectedSentEmail} />
            ) : (
              <div className="flex items-center justify-center h-full text-gray-500">
                Select an email to view
              </div>
            )
          )}
        </div>
      </main>

      {/* Compose modal */}
      {showCompose && (
        <ComposeModal
          fromAddress={emailAddress!}
          onClose={() => setShowCompose(false)}
          onSent={handleSend}
          onSuccess={() => showToast('Email sent successfully!')}
          initialTo={replyTo}
          initialSubject={replySubject}
          initialBody={replyBody}
        />
      )}

      {/* Toast notification */}
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}
    </div>
  );
}
