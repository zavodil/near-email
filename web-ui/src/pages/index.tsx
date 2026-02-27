import { useState, useEffect, useRef, useCallback } from 'react';
import type { AccountState } from '@near-wallet-selector/core';
import {
  showModal,
  signOut,
  getEmails,
  sendEmail,
  deleteEmail,
  initPaymentKey,
  setPaymentKey,
  setPaymentKeyEnabled,
  getPaymentKeyConfig,
  getPaymentKeyOwner,
  isPaymentKeyMode,
  checkUserRegistration,
  initSendPubkey,
  getSendPubkey,
  pollEmailCount,
  getStoredPollData,
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
import LimitsModal from '@/components/LimitsModal';
import Toast, { type ToastType } from '@/components/Toast';
import InviteCodeModal from '@/components/InviteCodeModal';
import InvitesModal from '@/components/InvitesModal';
import KeyCreationFlowModal from '@/components/KeyCreationFlowModal';

interface HomeProps {
  accounts: AccountState[];
  loading: boolean;
}

type Folder = 'inbox' | 'sent';

// Account validation
const ACCOUNT_SUFFIX = process.env.NEXT_PUBLIC_ACCOUNT_SUFFIX || 'near';

function validateAccountId(accountId: string): { valid: boolean; error?: string } {
  const suffix = `.${ACCOUNT_SUFFIX}`;

  // Check if account ends with the correct suffix
  if (!accountId.endsWith(suffix)) {
    return {
      valid: false,
      error: `Only .${ACCOUNT_SUFFIX} accounts are supported. Your account "${accountId}" is not a .${ACCOUNT_SUFFIX} account.`,
    };
  }

  // Check for subdomains (e.g., acc.name.near has 3 parts, alice.near has 2 parts)
  const parts = accountId.split('.');
  if (parts.length > 2) {
    return {
      valid: false,
      error: `Subdomain accounts are not supported. Please use a top-level account like "yourname.${ACCOUNT_SUFFIX}" instead of "${accountId}".`,
    };
  }

  return { valid: true };
}

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
  // Payment Key state
  const [paymentKeyEnabled, setPaymentKeyEnabledState] = useState(false);
  const [paymentKeyOwner, setPaymentKeyOwnerState] = useState<string | null>(null);
  const [paymentKeyHasKey, setPaymentKeyHasKey] = useState(false);
  const [showPaymentKeyInput, setShowPaymentKeyInput] = useState(false);
  const [paymentKeyInput, setPaymentKeyInput] = useState('');
  const [paymentKeyError, setPaymentKeyError] = useState<string | null>(null);
  // Limits modal state
  const [showLimitsModal, setShowLimitsModal] = useState(false);
  // Invite system state
  const [isRegistered, setIsRegistered] = useState<boolean | null>(null);
  const [invitesEnabled, setInvitesEnabled] = useState(true);
  const [showInviteCodeModal, setShowInviteCodeModal] = useState(false);
  const [showInvitesModal, setShowInvitesModal] = useState(false);
  const [inviteCodeFromUrl, setInviteCodeFromUrl] = useState<string | null>(null);
  const [checkingRegistration, setCheckingRegistration] = useState(false);
  const [showKeyCreationModal, setShowKeyCreationModal] = useState(false);

  // Polling and notification state
  const [newEmailCount, setNewEmailCount] = useState(0);
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission | null>(null);
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const lastPollTimeRef = useRef<number>(0);
  const isPollingRef = useRef<boolean>(false); // Prevent concurrent polls
  // Use ref for lastKnownInboxCount to avoid useCallback recreation on every poll
  const lastKnownInboxCountRef = useRef<number | null>(null);

  function showToast(message: string, type: ToastType = 'success') {
    setToast({ message, type });
  }

  function pluralize(count: number, singular: string, plural: string) {
    return count === 1 ? singular : plural;
  }

  // Initialize payment key from localStorage
  useEffect(() => {
    initPaymentKey();
    const config = getPaymentKeyConfig();
    setPaymentKeyEnabledState(config.enabled);
    setPaymentKeyOwnerState(config.owner);
    setPaymentKeyHasKey(config.hasKey);

    // Check for invite code in URL
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      const invite = params.get('invite');
      if (invite) {
        setInviteCodeFromUrl(invite.toUpperCase());
      }
    }
  }, []);

  const isConnected = accounts.length > 0;
  const accountId = isConnected ? accounts[0].accountId : null;

  // Effective account: payment key owner takes precedence when enabled
  const effectiveAccountId = paymentKeyEnabled && paymentKeyOwner
    ? paymentKeyOwner
    : accountId;

  // Validate account ID
  const accountValidation = effectiveAccountId ? validateAccountId(effectiveAccountId) : { valid: true };

  // Initialize send pubkey from localStorage when account changes
  // This allows Compose to work immediately after page reload (no transaction needed)
  useEffect(() => {
    if (effectiveAccountId) {
      initSendPubkey(effectiveAccountId);
    }
  }, [effectiveAccountId]);

  // Check registration status when account changes
  useEffect(() => {
    async function checkRegistration() {
      if (!effectiveAccountId) {
        setIsRegistered(null);
        return;
      }

      setCheckingRegistration(true);
      try {
        const result = await checkUserRegistration(effectiveAccountId);
        setInvitesEnabled(result.invites_enabled);
        setIsRegistered(result.registered);

        // If not registered and invites are enabled, show invite modal
        if (!result.registered && result.invites_enabled) {
          setShowInviteCodeModal(true);
        }
      } catch (err) {
        // If check fails, assume registered (allow access)
        console.error('Failed to check registration:', err);
        setIsRegistered(true);
      } finally {
        setCheckingRegistration(false);
      }
    }

    checkRegistration();
  }, [effectiveAccountId]);

  // Initialize notification permission
  useEffect(() => {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      setNotificationPermission(Notification.permission);
    }
  }, []);

  // Poll for new emails (uses ref to avoid recreating callback on every count change)
  const pollForNewEmails = useCallback(async () => {
    if (!effectiveAccountId) return;
    if (isPollingRef.current) return; // Prevent concurrent polls

    isPollingRef.current = true;
    try {
      const result = await pollEmailCount(effectiveAccountId);
      if (!result) return; // No token yet

      lastPollTimeRef.current = Date.now();
      const lastKnown = lastKnownInboxCountRef.current;

      // Calculate new emails since user last LOADED emails (not since last poll)
      // lastKnown = what user last SAW (only updated on loadEmails, not on poll)
      const newEmailsSinceLastSeen = lastKnown !== null ? Math.max(0, result.inbox - lastKnown) : 0;

      // Update newEmailCount state to reflect total unread
      // Only show notification if there are MORE new emails than we already notified about
      setNewEmailCount(prev => {
        if (newEmailsSinceLastSeen > prev) {
          // There are additional new emails since last notification
          const additionalNew = newEmailsSinceLastSeen - prev;
          console.log(`[Poll] New emails detected: +${additionalNew} (total unread: ${newEmailsSinceLastSeen}, lastSeen: ${lastKnown})`);

          // Update page title
          document.title = `(${newEmailsSinceLastSeen}) near.email`;

          // Show browser notification (check permission directly, not from state)
          const currentPermission = typeof Notification !== 'undefined' ? Notification.permission : 'denied';
          console.log(`[Poll] Notification permission: ${currentPermission}`);
          if (currentPermission === 'granted') {
            try {
              const notification = new Notification('near.email', {
                body: additionalNew === 1 ? 'You have a new email!' : `You have ${additionalNew} new emails!`,
                icon: '/favicon.ico',
                tag: 'new-email',
              });
              notification.onclick = () => {
                window.focus();
                notification.close();
              };
            } catch (e) {
              console.error('[Poll] Failed to show notification:', e);
            }
          }

          // Show toast
          console.log('[Poll] Showing toast...');
          showToast(
            additionalNew === 1 ? 'New email received!' : `${additionalNew} new emails received!`,
            'info'
          );

          return newEmailsSinceLastSeen;
        }
        // No new emails OR same count as before (already notified)
        return prev;
      });

      // NOTE: Do NOT update lastKnownInboxCountRef here!
      // It represents what user last SAW, only updated when user LOADS emails
      // This ensures reopening the page shows notification for unseen emails
    } finally {
      isPollingRef.current = false;
    }
  }, [effectiveAccountId, notificationPermission]);

  // Start polling immediately if poll_token exists (even before Check Email click)
  useEffect(() => {
    if (!effectiveAccountId) {
      return;
    }

    // Check if we have a stored poll token and initialize ref from localStorage
    const pollData = getStoredPollData(effectiveAccountId);
    if (pollData) {
      // IMPORTANT: Initialize ref BEFORE polling starts (fixes race condition)
      lastKnownInboxCountRef.current = pollData.lastKnownInboxCount;
      console.log(`[Poll] Restored lastKnownInboxCount from localStorage: ${pollData.lastKnownInboxCount}`);
    }

    if (!pollData && !hasCheckedMail) {
      // No stored token and user hasn't checked mail yet - don't poll
      return;
    }

    // Request notification permission
    if (notificationPermission === 'default' && 'Notification' in window) {
      Notification.requestPermission().then(permission => {
        setNotificationPermission(permission);
      });
    }

    // Poll every 30 seconds
    pollIntervalRef.current = setInterval(pollForNewEmails, 30000);

    // Also do an immediate poll if we have stored data (page reload scenario)
    if (pollData && !hasCheckedMail) {
      pollForNewEmails();
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [hasCheckedMail, effectiveAccountId, pollForNewEmails, notificationPermission]);

  // Handle visibility change (computer wake from sleep)
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && effectiveAccountId) {
        const timeSinceLastPoll = Date.now() - lastPollTimeRef.current;
        // If more than 5 seconds since last poll, check immediately
        // Works if user has checked mail OR has stored poll token
        const hasPollCapability = hasCheckedMail || getStoredPollData(effectiveAccountId);
        if (timeSinceLastPoll > 5000 && hasPollCapability) {
          pollForNewEmails();
        }
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [effectiveAccountId, hasCheckedMail, pollForNewEmails]);

  // Reset page title on unmount
  useEffect(() => {
    return () => {
      document.title = 'near.email';
    };
  }, []);

  // Update favicon based on new email count
  useEffect(() => {
    const updateFavicon = (hasNotification: boolean) => {
      // Update main .ico favicon
      const icoLink = document.querySelector("link[rel='icon'][sizes='any']") as HTMLLinkElement | null;
      if (icoLink) {
        icoLink.href = hasNotification ? '/favicon-notification.ico' : '/favicon.ico';
      }
      // Fallback: update first icon link if specific selector didn't match
      if (!icoLink) {
        const fallbackLink = document.querySelector("link[rel~='icon']") as HTMLLinkElement | null;
        if (fallbackLink) {
          fallbackLink.href = hasNotification ? '/favicon-notification.ico' : '/favicon.ico';
        }
      }
    };

    updateFavicon(newEmailCount > 0);

    // Cleanup: reset favicon on unmount
    return () => {
      updateFavicon(false);
    };
  }, [newEmailCount]);

  // Handle both .near and .testnet suffixes
  const emailAddress = effectiveAccountId
    ? `${effectiveAccountId.replace('.near', '').replace('.testnet', '')}@near.email`
    : null;

  // Can use app if wallet connected OR payment key enabled
  const canUseApp = isConnected || paymentKeyEnabled;

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

      // Update lastKnownInboxCount to what user just SAW
      // near.ts now updates localStorage with actual inbox_count from server
      // We just need to sync our ref
      const serverCount = result.inboxCount ?? result.inbox.length;
      lastKnownInboxCountRef.current = serverCount;
      console.log(`[loadEmails] Updated lastKnownInboxCount to ${serverCount}`)

      setNewEmailCount(0); // Clear badge - user has seen all emails now
      document.title = 'near.email'; // Reset title
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
    // NOTE: Do NOT clear newEmailCount here - it should only be cleared
    // when emails are actually loaded from server (in loadEmails)
  }

  function handleConnect() {
    showModal();
  }

  // Sign out wallet only (keeps payment key if configured)
  async function handleSignOutWallet() {
    await signOut();
    setEmails([]);
    setSentEmails([]);
    setSelectedEmail(null);
    setSelectedSentEmail(null);
    setHasCheckedMail(false);
    setInboxNextOffset(null);
    setSentNextOffset(null);
  }

  // Full disconnect - sign out wallet AND clear payment key
  async function handleDisconnect() {
    await signOut();
    // Also clear payment key (full sign out)
    setPaymentKey(null);
    setPaymentKeyEnabledState(false);
    setPaymentKeyOwnerState(null);
    setPaymentKeyHasKey(false);
    setEmails([]);
    setSentEmails([]);
    setSelectedEmail(null);
    setSelectedSentEmail(null);
    setHasCheckedMail(false);
    setInboxNextOffset(null);
    setSentNextOffset(null);
  }

  // Payment Key handlers
  function handlePaymentKeyToggle() {
    const newEnabled = !paymentKeyEnabled;
    setPaymentKeyEnabled(newEnabled);
    setPaymentKeyEnabledState(newEnabled);
    // Clear cached emails since user identity may change
    setEmails([]);
    setSentEmails([]);
    setHasCheckedMail(false);
  }

  async function handleSavePaymentKey() {
    setPaymentKeyError(null);
    const success = setPaymentKey(paymentKeyInput.trim());
    if (success) {
      const config = getPaymentKeyConfig();
      setPaymentKeyEnabledState(config.enabled);
      setPaymentKeyOwnerState(config.owner);
      setPaymentKeyHasKey(config.hasKey);
      setShowPaymentKeyInput(false);
      setPaymentKeyInput('');
      // Auto-reload emails with new identity
      setEmails([]);
      setSentEmails([]);
      setHasCheckedMail(true); // Skip "Check Mail" screen
      setLoadingEmails(true);
      try {
        const result = await getEmails(0, 0);
        updateFromResult(result);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoadingEmails(false);
      }
    } else {
      setPaymentKeyError('Invalid format. Expected: owner:nonce:key');
    }
  }

  function handleClearPaymentKey() {
    setPaymentKey(null);
    setPaymentKeyEnabledState(false);
    setPaymentKeyOwnerState(null);
    setPaymentKeyHasKey(false);
    // Clear cached emails
    setEmails([]);
    setSentEmails([]);
    setHasCheckedMail(false);
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
    // Show inbox after sending (server returns mail data)
    setHasCheckedMail(true);
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

  // Invalid account screen - account doesn't meet requirements
  if (canUseApp && !accountValidation.valid) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-gradient-to-br from-gray-50 to-gray-100">
        <h1 className="text-3xl font-bold text-gray-900 mb-6">near.email</h1>

        <div className="bg-white rounded-2xl shadow-xl border border-gray-100 p-6 max-w-md w-full text-center">
          <div className="w-14 h-14 bg-gradient-to-br from-red-400 to-red-600 rounded-full flex items-center justify-center text-white text-xl mx-auto mb-4">
            <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <p className="text-sm text-gray-500 mb-1">Connected as</p>
          <p className="font-semibold text-gray-900 mb-4">{effectiveAccountId}</p>

          <div className="bg-red-50 text-red-700 px-4 py-3 rounded-lg text-sm mb-6 border border-red-100 text-left">
            {accountValidation.error}
          </div>

          <button
            onClick={handleDisconnect}
            className="w-full bg-gray-900 text-white py-2.5 px-6 rounded-xl font-medium hover:bg-gray-800 transition-colors shadow-sm"
          >
            Disconnect & Try Another Account
          </button>
        </div>

        <p className="text-xs text-gray-400 mt-6">
          Powered by{' '}
          <a href="https://outlayer.fastnear.com" target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline">NEAR Outlayer</a>
          {' '}&bull;{' '}
          <a href="/docs" className="text-blue-500 hover:underline">Docs</a>
          {' '}&bull;{' '}
          <a href="/dev" className="text-blue-500 hover:underline">SDK</a>
        </p>
      </div>
    );
  }

  // Check mail screen - can use app but hasn't checked yet
  if (canUseApp && !hasCheckedMail) {
    // Show checking registration spinner
    if (checkingRegistration) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100">
          <div className="text-center">
            <div className="inline-block w-8 h-8 border-3 border-gray-200 border-t-purple-500 rounded-full animate-spin mb-4"></div>
            <p className="text-gray-500">Checking access...</p>
          </div>
        </div>
      );
    }

    // Show invite code modal if not registered (and invites are enabled)
    if (invitesEnabled && isRegistered === false) {
      return (
        <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-gradient-to-br from-gray-50 to-gray-100">
          <h1 className="text-3xl font-bold text-gray-900 mb-6">near.email</h1>
          <InviteCodeModal
            accountId={effectiveAccountId!}
            initialCode={inviteCodeFromUrl || ''}
            onSuccess={() => {
              setIsRegistered(true);
              setShowInviteCodeModal(false);
              // Clear invite code from URL
              if (typeof window !== 'undefined' && inviteCodeFromUrl) {
                window.history.replaceState({}, '', window.location.pathname);
              }
            }}
            onCancel={handleDisconnect}
          />
        </div>
      );
    }

    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-gradient-to-br from-gray-50 to-gray-100">
        <div className="bg-white rounded-2xl shadow-xl border border-gray-100 p-6 max-w-sm w-full text-center">
          <div className="flex items-center justify-center gap-3 mb-6 mt-3">
            <img src="/logo.png" alt="" className="w-10 h-auto sm:w-12" />
            <h1 className="text-3xl font-bold text-gray-900">near.email</h1>
          </div>
          <p className="text-sm text-gray-500 mb-1">Connected as</p>
          <p className="font-semibold text-gray-900 mb-1">{effectiveAccountId}</p>
          <p className="text-sm text-gray-400 mb-6">{emailAddress}</p>

          {error && (
            <div className="bg-red-50 text-red-700 px-3 py-2 rounded-lg text-sm mb-4 border border-red-100">
              {error}
            </div>
          )}

          {/* New email notification on Check Mail screen */}
          {newEmailCount > 0 && (
            <div className="bg-blue-50 text-blue-700 px-3 py-2 rounded-lg text-sm mb-4 border border-blue-200 flex items-center gap-2 animate-pulse">
              <svg className="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              {newEmailCount === 1 ? 'You have 1 new email!' : `You have ${newEmailCount} new emails!`}
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
                {newEmailCount > 0 ? `Check Mail (${newEmailCount} new)` : 'Check Mail'}
              </>
            )}
          </button>

          {/* Compose button - enabled if send pubkey is cached from previous session */}
          {getSendPubkey() && (
            <button
              onClick={handleOpenCompose}
              disabled={loadingEmails}
              className="w-full mt-3 bg-blue-50 text-blue-700 py-2.5 px-6 rounded-xl font-medium border border-blue-200 hover:bg-blue-100 transition-colors disabled:opacity-50 shadow-sm flex items-center justify-center gap-2"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Compose Email
            </button>
          )}

          {isConnected && !paymentKeyHasKey && (
            <>
              <div className="mt-3 border-t border-gray-200" />
              <button
                onClick={() => setShowPaymentKeyInput(true)}
                className="w-full mt-3 bg-white text-gray-600 py-2.5 px-6 rounded-xl font-medium border border-gray-200 hover:bg-gray-50 transition-colors shadow-sm"
              >
                Login with Payment Key
              </button>
            </>
          )}

          <button
            onClick={handleDisconnect}
            className="mt-2 text-sm text-gray-400 hover:text-red-600 transition-colors"
          >
            Sign out
          </button>
        </div>

        <p className="text-xs text-gray-400 mt-6">
          Powered by{' '}
          <a href="https://outlayer.fastnear.com" target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline">NEAR Outlayer</a>
          {' '}&bull;{' '}
          <a href="/docs" className="text-blue-500 hover:underline">Docs</a>
          {' '}&bull;{' '}
          <a href="/dev" className="text-blue-500 hover:underline">SDK</a>
        </p>

        {/* Compose modal (for early compose before checking mail) */}
        {showCompose && (
          <ComposeModal
            fromAddress={emailAddress!}
            onClose={() => setShowCompose(false)}
            onSent={handleSend}
            onSuccess={() => showToast('Email sent successfully!')}
            onOpenInvites={invitesEnabled ? () => setShowInvitesModal(true) : undefined}
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

        {/* Payment Key input modal */}
        {showPaymentKeyInput && (
          <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl shadow-xl p-4 w-full max-w-xl mx-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                Configure Payment Key
              </h3>
              <p className="text-sm text-gray-500 mb-4">
                Enter your Payment Key to use near.email without wallet transactions.
              </p>

              {paymentKeyError && (
                <div className="bg-red-50 text-red-700 px-3 py-2 rounded-lg text-sm mb-3 border border-red-100">
                  {paymentKeyError}
                </div>
              )}

              <input
                type="text"
                value={paymentKeyInput}
                onChange={(e) => setPaymentKeyInput(e.target.value)}
                placeholder="alice.near:1:abcd1234..."
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                onKeyDown={(e) => e.key === 'Enter' && handleSavePaymentKey()}
              />
              <p className="text-xs text-gray-400 mt-1">
                Format: owner:nonce:key
              </p>

              <div className="flex justify-end gap-2 mt-4">
                <button
                  onClick={() => {
                    setShowPaymentKeyInput(false);
                    setPaymentKeyInput('');
                    setPaymentKeyError(null);
                  }}
                  className="px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-100 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSavePaymentKey}
                  className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Save
                </button>
              </div>

              {isConnected && accountId && (
                <>
                  <div className="flex items-center gap-3 my-4">
                    <div className="flex-1 h-px bg-gray-200"></div>
                    <span className="text-xs text-gray-400">or</span>
                    <div className="flex-1 h-px bg-gray-200"></div>
                  </div>

                  <button
                    onClick={() => {
                      setShowPaymentKeyInput(false);
                      setShowKeyCreationModal(true);
                    }}
                    className="w-full text-sm text-gray-600 hover:text-gray-900 py-2 px-3 rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors"
                  >
                    Buy Payment Key with NEAR
                  </button>
                  <p className="text-xs text-gray-400 mt-1 text-center">
                    Your NEAR will be converted to USDC. Usage fees are deducted from the balance.
                  </p>
                </>
              )}
            </div>
          </div>
        )}

        {/* Key Creation Flow Modal */}
        {showKeyCreationModal && accountId && (
          <KeyCreationFlowModal
            accountId={accountId}
            onComplete={(paymentKey) => {
              // Save the newly created payment key
              setPaymentKey(paymentKey);
              const config = getPaymentKeyConfig();
              setPaymentKeyEnabledState(config.enabled);
              setPaymentKeyOwnerState(config.owner);
              setPaymentKeyHasKey(config.hasKey);
              setShowKeyCreationModal(false);
              showToast('Payment Key created! You can now use HTTPS mode.');
            }}
            onCancel={() => setShowKeyCreationModal(false)}
          />
        )}
      </div>
    );
  }

  // Landing page for users who cannot use app yet
  if (!canUseApp) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-gradient-to-br from-gray-50 to-gray-100">
        <div className="text-center mb-8">
          <img
            src="/logo.png"
            alt="near.email"
            className="w-16 h-auto sm:w-24 mx-auto mb-4"
          />
          <h1 className="text-4xl font-bold text-gray-900 mb-2">near.email</h1>
          <p className="text-lg text-gray-600 font-medium">
            Blockchain-native email
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
                <p className="text-sm font-medium text-gray-800">Your wallet = your mailbox</p>
                <p className="text-sm text-gray-600 font-mono">alice.near → alice@near.email</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 bg-cyan-100 rounded-lg flex items-center justify-center flex-shrink-0">
                <svg className="w-4 h-4 text-cyan-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-800">Real email. Send to anyone.</p>
                <p className="text-xs text-gray-500">Gmail, Outlook, any address works.</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center flex-shrink-0">
                <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-800">No one reads your mail. Ever.</p>
                <p className="text-xs text-gray-500">No password. Only your wallet decrypts.</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 bg-purple-100 rounded-lg flex items-center justify-center flex-shrink-0">
                <svg className="w-4 h-4 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-gray-800">TEE attestation on every action</p>
                <p className="text-xs text-gray-500">Signed by Intel. Verifiable by anyone.</p>
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

          <button
            onClick={() => setShowPaymentKeyInput(true)}
            className="mt-3 text-sm text-gray-400 hover:text-blue-600 transition-colors"
          >
            Login with Payment Key
          </button>
        </div>

        <p className="text-xs text-gray-400 mt-6">
          Powered by{' '}
          <a href="https://outlayer.fastnear.com" target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline">NEAR Outlayer</a>
          {' '}&bull;{' '}
          <a href="/docs" className="text-blue-500 hover:underline">Docs</a>
          {' '}&bull;{' '}
          <a href="/dev" className="text-blue-500 hover:underline">SDK</a>
        </p>

        {/* Payment Key input modal */}
        {showPaymentKeyInput && (
          <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl shadow-xl p-4 w-full max-w-xl mx-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                Configure Payment Key
              </h3>
              <p className="text-sm text-gray-500 mb-4">
                Enter your Payment Key to use near.email without wallet transactions.
              </p>

              {paymentKeyError && (
                <div className="bg-red-50 text-red-700 px-3 py-2 rounded-lg text-sm mb-3 border border-red-100">
                  {paymentKeyError}
                </div>
              )}

              <input
                type="text"
                value={paymentKeyInput}
                onChange={(e) => setPaymentKeyInput(e.target.value)}
                placeholder="alice.near:1:abcd1234..."
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                onKeyDown={(e) => e.key === 'Enter' && handleSavePaymentKey()}
              />
              <p className="text-xs text-gray-400 mt-1">
                Format: owner:nonce:key
              </p>

              <div className="flex justify-end gap-2 mt-4">
                <button
                  onClick={() => {
                    setShowPaymentKeyInput(false);
                    setPaymentKeyInput('');
                    setPaymentKeyError(null);
                  }}
                  className="px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-100 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSavePaymentKey}
                  className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Save
                </button>
              </div>

              {isConnected && accountId && (
                <>
                  <div className="flex items-center gap-3 my-4">
                    <div className="flex-1 h-px bg-gray-200"></div>
                    <span className="text-xs text-gray-400">or</span>
                    <div className="flex-1 h-px bg-gray-200"></div>
                  </div>

                  <button
                    onClick={() => {
                      setShowPaymentKeyInput(false);
                      setShowKeyCreationModal(true);
                    }}
                    className="w-full text-sm text-gray-600 hover:text-gray-900 py-2 px-3 rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors"
                  >
                    Buy Payment Key with NEAR
                  </button>
                  <p className="text-xs text-gray-400 mt-1 text-center">
                    Your NEAR will be converted to USDC. Usage fees are deducted from the balance.
                  </p>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    );
  }

  // Email interface for connected users
  return (
    <div className="min-h-screen flex flex-col bg-gray-50">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm border-b border-gray-100 px-4 py-3 flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center gap-2">
          <img src="/logo.png" alt="" className="w-7 h-auto sm:w-8" />
          <h1 className="text-lg font-semibold text-gray-900">near.email</h1>
          <span className="text-xs text-gray-400 hidden sm:inline">{emailAddress}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleOpenCompose}
            className="ml-2 flex items-center gap-1.5 bg-blue-600 text-white px-3 py-1.5 text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors shadow-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Compose
          </button>
          {/* Invites button */}
          {invitesEnabled && (
            <button
              onClick={() => setShowInvitesModal(true)}
              className="p-2 text-gray-400 hover:text-purple-600 hover:bg-purple-50 rounded-lg transition-colors"
              title="Invites"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
              </svg>
            </button>
          )}
          {/* Account dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowAccountMenu(!showAccountMenu)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <div className="w-6 h-6 bg-gradient-to-br from-blue-400 to-blue-600 rounded-full flex items-center justify-center text-white text-xs font-medium">
                {effectiveAccountId?.charAt(0).toUpperCase()}
              </div>
              <span className="hidden sm:inline max-w-[120px] truncate">{effectiveAccountId}</span>
              <svg className="w-3.5 h-3.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {showAccountMenu && (
              <div className="absolute right-0 mt-1 w-64 bg-white rounded-lg shadow-lg border border-gray-100 py-1 z-50">
                {/* Current account info */}
                <div className="px-3 py-2 border-b border-gray-100">
                  {paymentKeyEnabled ? (
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <span className="text-[10px] font-medium text-green-700 bg-green-100 px-1.5 py-0.5 rounded">HTTPS</span>
                      <span className="text-[10px] text-gray-400">18 MB attachments</span>
                    </div>
                  ) : (
                    <p className="text-xs text-gray-400">Signed in as</p>
                  )}
                  <p className="text-sm font-medium text-gray-700 truncate">{effectiveAccountId}</p>
                </div>

                {/* Payment Key section */}
                <div className="px-3 py-2 border-b border-gray-100">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-600">Payment Key</span>
                    <button
                      onClick={handlePaymentKeyToggle}
                      disabled={!paymentKeyHasKey}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                        paymentKeyEnabled ? 'bg-blue-600' : 'bg-gray-300'
                      } ${!paymentKeyHasKey ? 'opacity-50 cursor-not-allowed' : ''}`}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                          paymentKeyEnabled ? 'translate-x-4' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>

                  {paymentKeyOwner && (
                    <p className="text-xs text-gray-400 mt-1 truncate">
                      {paymentKeyOwner}:*
                    </p>
                  )}

                  <div className="mt-2 flex gap-2">
                    <button
                      onClick={() => setShowPaymentKeyInput(true)}
                      className="text-xs text-blue-600 hover:text-blue-700"
                    >
                      {paymentKeyHasKey ? 'Change' : 'Configure'}
                    </button>
                    {paymentKeyHasKey && (
                      <button
                        onClick={handleClearPaymentKey}
                        className="text-xs text-red-600 hover:text-red-700"
                      >
                        Clear
                      </button>
                    )}
                  </div>
                </div>

                {/* Invites & Limits & Docs links */}
                <div className="border-b border-gray-100">
                  <button
                    onClick={() => {
                      setShowInvitesModal(true);
                      setShowAccountMenu(false);
                    }}
                    className="w-full text-left px-3 py-2 text-sm text-purple-600 hover:bg-purple-50 transition-colors flex items-center gap-2"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
                    </svg>
                    Invite friends
                  </button>
                  <button
                    onClick={() => {
                      setShowLimitsModal(true);
                      setShowAccountMenu(false);
                    }}
                    className="w-full text-left px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 transition-colors flex items-center gap-2"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Size limits
                  </button>
                  <a
                    href="/docs"
                    className="w-full text-left px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 transition-colors flex items-center gap-2"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
                    </svg>
                    How it works
                  </a>
                  <a
                    href="/dev"
                    className="w-full text-left px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 transition-colors flex items-center gap-2"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                    </svg>
                    Developer Docs
                  </a>
                </div>

                {/* External links */}
                <div className="border-b border-gray-100">
                  <a
                    href="https://github.com/zavodil/near-email"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="w-full text-left px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 transition-colors flex items-center gap-2"
                  >
                    <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                      <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                    </svg>
                    NEAR Email GitHub
                  </a>
                  <a
                    href="https://github.com/fastnear/near-outlayer"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="w-full text-left px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 transition-colors flex items-center gap-2"
                  >
                    <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                      <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                    </svg>
                    OutLayer GitHub
                  </a>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText('npx openskills install zavodil/near-email-skill');
                      setShowAccountMenu(false);
                    }}
                    className="w-full text-left px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 transition-colors flex items-center gap-2"
                    title="Copy to clipboard"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                    </svg>
                    Claude Code Skill
                  </button>
                </div>

                {/* Sign out button (only when wallet connected) */}
                {isConnected && (
                  <button
                    onClick={() => {
                      handleSignOutWallet();
                      setShowAccountMenu(false);
                    }}
                    className="w-full text-left px-3 py-2 text-sm text-red-600 hover:bg-red-50 transition-colors"
                  >
                    Sign out wallet
                  </button>
                )}
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
              className={`flex-1 py-2.5 text-center text-sm font-medium transition-colors relative ${
                currentFolder === 'inbox'
                  ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50/50'
                  : 'text-gray-500 hover:bg-gray-50'
              }`}
            >
              Inbox ({emails.length}{inboxNextOffset ? '+' : ''} {pluralize(emails.length, 'email', 'emails')})
              {newEmailCount > 0 && currentFolder !== 'inbox' && (
                <span className="absolute top-1 right-2 bg-red-500 text-white text-xs rounded-full px-1.5 py-0.5 min-w-[18px] animate-pulse">
                  {newEmailCount > 99 ? '99+' : newEmailCount}
                </span>
              )}
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

          {/* New emails banner - shows when polling detects new emails */}
          {newEmailCount > 0 && currentFolder === 'inbox' && (
            <button
              onClick={loadEmails}
              className="w-full px-3 py-2 bg-blue-50 border-b border-blue-200 text-blue-700 text-sm font-medium hover:bg-blue-100 transition-colors flex items-center justify-center gap-2"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              {newEmailCount === 1 ? '1 new email' : `${newEmailCount} new emails`} — click to refresh
            </button>
          )}

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
          onShowLimits={() => setShowLimitsModal(true)}
          onOpenInvites={invitesEnabled ? () => setShowInvitesModal(true) : undefined}
          initialTo={replyTo}
          initialSubject={replySubject}
          initialBody={replyBody}
        />
      )}

      {/* Limits modal */}
      <LimitsModal
        isOpen={showLimitsModal}
        onClose={() => setShowLimitsModal(false)}
        isHttpsMode={isPaymentKeyMode()}
      />

      {/* Invites modal */}
      <InvitesModal
        accountId={effectiveAccountId || ''}
        isOpen={showInvitesModal}
        onClose={() => setShowInvitesModal(false)}
        walletConnected={isConnected}
        onConnectWallet={() => {
          setShowInvitesModal(false);
          showModal();
        }}
        walletAccountId={accountId}
        paymentKeyOwner={paymentKeyEnabled ? paymentKeyOwner : null}
      />

      {/* Toast notification */}
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={() => setToast(null)}
        />
      )}

      {/* Payment Key input modal */}
      {showPaymentKeyInput && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-xl p-4 w-full max-w-xl mx-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-2">
              Configure Payment Key
            </h3>
            <p className="text-sm text-gray-500 mb-4">
              Enter your Payment Key to use near.email without wallet transactions.
            </p>

            {paymentKeyError && (
              <div className="bg-red-50 text-red-700 px-3 py-2 rounded-lg text-sm mb-3 border border-red-100">
                {paymentKeyError}
              </div>
            )}

            <input
              type="text"
              value={paymentKeyInput}
              onChange={(e) => setPaymentKeyInput(e.target.value)}
              placeholder="alice.near:1:abcd1234..."
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
              onKeyDown={(e) => e.key === 'Enter' && handleSavePaymentKey()}
            />
            <p className="text-xs text-gray-400 mt-1">
              Format: owner:nonce:key
            </p>

            <div className="flex justify-end gap-2 mt-4">
              <button
                onClick={() => {
                  setShowPaymentKeyInput(false);
                  setPaymentKeyInput('');
                  setPaymentKeyError(null);
                }}
                className="px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-100 rounded-lg"
              >
                Cancel
              </button>
              <button
                onClick={handleSavePaymentKey}
                className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Save
              </button>
            </div>

            {isConnected && accountId && (
              <>
                <div className="flex items-center gap-3 my-4">
                  <div className="flex-1 h-px bg-gray-200"></div>
                  <span className="text-xs text-gray-400">or</span>
                  <div className="flex-1 h-px bg-gray-200"></div>
                </div>

                <button
                  onClick={() => {
                    setShowPaymentKeyInput(false);
                    setShowKeyCreationModal(true);
                  }}
                  className="w-full text-sm text-gray-600 hover:text-gray-900 py-2 px-3 rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors"
                >
                  Buy Payment Key with NEAR
                </button>
                <p className="text-xs text-gray-400 mt-1 text-center">
                  Your NEAR will be converted to USDC. Usage fees are deducted from the balance.
                </p>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
