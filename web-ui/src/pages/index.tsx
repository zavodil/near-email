import { useState, useEffect } from 'react';
import type { AccountState } from '@near-wallet-selector/core';
import { showModal, signOut, getEmails, type Email } from '@/lib/near';
import EmailList from '@/components/EmailList';
import EmailView from '@/components/EmailView';
import ComposeModal from '@/components/ComposeModal';

interface HomeProps {
  accounts: AccountState[];
  loading: boolean;
}

export default function Home({ accounts, loading }: HomeProps) {
  const [emails, setEmails] = useState<Email[]>([]);
  const [selectedEmail, setSelectedEmail] = useState<Email | null>(null);
  const [emailCount, setEmailCount] = useState<number | null>(null);
  const [loadingEmails, setLoadingEmails] = useState(false);
  const [showCompose, setShowCompose] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasCheckedMail, setHasCheckedMail] = useState(false);
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

  async function loadEmails() {
    setLoadingEmails(true);
    setError(null);
    try {
      const emailList = await getEmails();
      setEmails(emailList);
      setEmailCount(emailList.length);
      setHasCheckedMail(true);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoadingEmails(false);
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
          <button
            onClick={loadEmails}
            disabled={loadingEmails}
            className="text-gray-600 hover:text-gray-900 transition-colors"
          >
            {loadingEmails ? 'Loading...' : 'Refresh'}
          </button>
          <div className="text-gray-600">
            {accountId}
          </div>
          <button
            onClick={handleDisconnect}
            className="text-red-600 hover:text-red-700 transition-colors"
          >
            Disconnect
          </button>
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
      <main className="flex-1 flex">
        {/* Email list */}
        <div className="w-1/3 border-r bg-white overflow-y-auto">
          <div className="p-4 border-b bg-gray-50">
            <span className="text-gray-600">{emailCount ?? 0} emails</span>
          </div>
          <EmailList
            emails={emails}
            selectedId={selectedEmail?.id}
            onSelect={setSelectedEmail}
            loading={loadingEmails}
          />
        </div>

        {/* Email view */}
        <div className="flex-1 bg-gray-50">
          {selectedEmail ? (
            <EmailView
              email={selectedEmail}
              onDelete={async () => {
                setSelectedEmail(null);
                await loadEmails();
              }}
              onReply={handleReply}
            />
          ) : (
            <div className="flex items-center justify-center h-full text-gray-500">
              Select an email to read
            </div>
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
