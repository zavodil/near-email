import { useState, useEffect } from 'react';
import type { AccountState } from '@near-wallet-selector/core';
import { showModal, signOut, getEmails, getSentEmails, type Email, type SentEmail } from '@/lib/near';
import EmailList from '@/components/EmailList';
import SentEmailList from '@/components/SentEmailList';
import EmailView from '@/components/EmailView';
import SentEmailView from '@/components/SentEmailView';
import ComposeModal from '@/components/ComposeModal';

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
  const [emailCount, setEmailCount] = useState<number | null>(null);
  const [sentEmailCount, setSentEmailCount] = useState<number | null>(null);
  const [loadingEmails, setLoadingEmails] = useState(false);
  const [loadingSent, setLoadingSent] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [showCompose, setShowCompose] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasCheckedMail, setHasCheckedMail] = useState(false);
  const [showAccountMenu, setShowAccountMenu] = useState(false);
  const [hasMoreEmails, setHasMoreEmails] = useState(false);
  const [hasMoreSentEmails, setHasMoreSentEmails] = useState(false);
  const [currentFolder, setCurrentFolder] = useState<Folder>('inbox');
  // Reply state
  const [replyTo, setReplyTo] = useState('');
  const [replySubject, setReplySubject] = useState('');
  const [replyBody, setReplyBody] = useState('');

  const isConnected = accounts.length > 0;
  const accountId = isConnected ? accounts[0].accountId : null;
  // Handle both .near and .testnet suffixes
  const emailAddress = accountId
    ? `${accountId.replace('.near', '').replace('.testnet', '')}@near.email`
    : null;

  const PAGE_SIZE = 50;

  async function loadEmails() {
    setLoadingEmails(true);
    setError(null);
    try {
      const emailList = await getEmails(PAGE_SIZE, 0);
      setEmails(emailList);
      setEmailCount(emailList.length);
      setHasMoreEmails(emailList.length === PAGE_SIZE);
      setHasCheckedMail(true);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoadingEmails(false);
    }
  }

  async function loadMoreEmails() {
    setLoadingMore(true);
    setError(null);
    try {
      const moreEmails = await getEmails(PAGE_SIZE, emails.length);
      const newEmails = [...emails, ...moreEmails];
      setEmails(newEmails);
      setEmailCount(newEmails.length);
      setHasMoreEmails(moreEmails.length === PAGE_SIZE);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoadingMore(false);
    }
  }

  async function loadSentEmails() {
    setLoadingSent(true);
    setError(null);
    try {
      const sentList = await getSentEmails(PAGE_SIZE, 0);
      setSentEmails(sentList);
      setSentEmailCount(sentList.length);
      setHasMoreSentEmails(sentList.length === PAGE_SIZE);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoadingSent(false);
    }
  }

  async function loadMoreSentEmails() {
    setLoadingMore(true);
    setError(null);
    try {
      const moreSent = await getSentEmails(PAGE_SIZE, sentEmails.length);
      const newSent = [...sentEmails, ...moreSent];
      setSentEmails(newSent);
      setSentEmailCount(newSent.length);
      setHasMoreSentEmails(moreSent.length === PAGE_SIZE);
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
    // Load sent emails if switching to sent folder and not loaded yet
    if (folder === 'sent' && sentEmails.length === 0 && !loadingSent) {
      loadSentEmails();
    }
  }

  function handleConnect() {
    showModal();
  }

  async function handleDisconnect() {
    await signOut();
    setEmails([]);
    setSelectedEmail(null);
    setEmailCount(null);
    setHasCheckedMail(false);
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

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-xl text-gray-600">Loading...</div>
      </div>
    );
  }

  // Check mail screen - connected but hasn't checked yet
  if (isConnected && !hasCheckedMail) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-8">
        <h1 className="text-5xl font-bold text-gray-900 mb-4">near.email</h1>

        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full text-center">
          <p className="text-gray-600 mb-2">Connected as</p>
          <p className="text-xl font-semibold text-gray-900 mb-2">{accountId}</p>
          <p className="text-gray-500 mb-6">{emailAddress}</p>

          {error && (
            <div className="bg-red-100 text-red-700 p-3 rounded-lg mb-4">
              {error}
            </div>
          )}

          <button
            onClick={loadEmails}
            disabled={loadingEmails}
            className="w-full bg-blue-600 text-white py-3 px-6 rounded-lg font-semibold hover:bg-blue-700 transition-colors disabled:opacity-50 mb-4"
          >
            {loadingEmails ? 'Loading...' : 'Check Mail'}
          </button>

          <button
            onClick={handleDisconnect}
            className="text-red-600 hover:text-red-700 transition-colors"
          >
            Disconnect
          </button>
        </div>
      </div>
    );
  }

  // Landing page for non-connected users
  if (!isConnected) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-8">
        <h1 className="text-5xl font-bold text-gray-900 mb-4">near.email</h1>
        <p className="text-xl text-gray-600 mb-8 text-center max-w-md">
          Blockchain-native email for NEAR accounts.
          <br />
          Your account, your inbox.
        </p>

        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md w-full">
          <h2 className="text-2xl font-semibold mb-4 text-center">How it works</h2>
          <ul className="space-y-3 text-gray-700 mb-6">
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              Every NEAR account has an email: <code className="bg-gray-100 px-1 rounded">alice.near → alice@near.email</code>
            </li>
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              Only you can read your emails (cryptographically enforced)
            </li>
            <li className="flex items-start">
              <span className="text-green-500 mr-2">✓</span>
              No registration required — just connect your wallet
            </li>
          </ul>

          <button
            onClick={handleConnect}
            className="w-full bg-blue-600 text-white py-3 px-6 rounded-lg font-semibold hover:bg-blue-700 transition-colors"
          >
            Connect NEAR Wallet
          </button>
        </div>
      </div>
    );
  }

  // Email interface for connected users
  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="bg-white border-b px-6 py-4 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">near.email</h1>
          <p className="text-sm text-gray-500">{emailAddress}</p>
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={handleOpenCompose}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Compose
          </button>
          {/* Account dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowAccountMenu(!showAccountMenu)}
              className="flex items-center gap-2 text-gray-700 hover:text-gray-900 transition-colors"
            >
              <span>{accountId}</span>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {showAccountMenu && (
              <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border py-1 z-50">
                <button
                  onClick={() => {
                    handleDisconnect();
                    setShowAccountMenu(false);
                  }}
                  className="w-full text-left px-4 py-2 text-red-600 hover:bg-gray-100 transition-colors"
                >
                  Disconnect
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Error banner */}
      {error && (
        <div className="bg-red-100 border-b border-red-200 px-6 py-3 text-red-700">
          {error}
          <button onClick={() => setError(null)} className="ml-4 underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Main content */}
      <main className="flex-1 flex" onClick={() => showAccountMenu && setShowAccountMenu(false)}>
        {/* Email list */}
        <div className="w-1/3 border-r bg-white overflow-y-auto flex flex-col">
          {/* Folder tabs */}
          <div className="flex border-b">
            <button
              onClick={() => handleFolderChange('inbox')}
              className={`flex-1 py-3 text-center font-medium transition-colors ${
                currentFolder === 'inbox'
                  ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50'
                  : 'text-gray-600 hover:bg-gray-50'
              }`}
            >
              Inbox
            </button>
            <button
              onClick={() => handleFolderChange('sent')}
              className={`flex-1 py-3 text-center font-medium transition-colors ${
                currentFolder === 'sent'
                  ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50'
                  : 'text-gray-600 hover:bg-gray-50'
              }`}
            >
              Sent
            </button>
          </div>

          {/* Email count and refresh */}
          <div className="p-4 border-b bg-gray-50 flex items-center justify-between">
            <span className="text-gray-600">
              {currentFolder === 'inbox' ? (emailCount ?? 0) : (sentEmailCount ?? 0)} emails
            </span>
            <button
              onClick={currentFolder === 'inbox' ? loadEmails : loadSentEmails}
              disabled={currentFolder === 'inbox' ? loadingEmails : loadingSent}
              className="p-1 text-gray-500 hover:text-gray-700 transition-colors disabled:opacity-50"
              title="Refresh"
            >
              <svg className={`w-5 h-5 ${(currentFolder === 'inbox' ? loadingEmails : loadingSent) ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
                {hasMoreEmails && !loadingEmails && (
                  <div className="p-4 border-t">
                    <button
                      onClick={loadMoreEmails}
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
                  loading={loadingSent}
                />
                {hasMoreSentEmails && !loadingSent && (
                  <div className="p-4 border-t">
                    <button
                      onClick={loadMoreSentEmails}
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
        <div className="flex-1 bg-gray-50">
          {currentFolder === 'inbox' ? (
            selectedEmail ? (
              <EmailView
                email={selectedEmail}
                onDelete={() => {
                  setEmails(emails.filter(e => e.id !== selectedEmail.id));
                  setEmailCount((emailCount ?? 1) - 1);
                  setSelectedEmail(null);
                  alert('Email deleted. Click Refresh to update the list.');
                }}
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
          onSent={() => {
            setShowCompose(false);
          }}
          initialTo={replyTo}
          initialSubject={replySubject}
          initialBody={replyBody}
        />
      )}
    </div>
  );
}
