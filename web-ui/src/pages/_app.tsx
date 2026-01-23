import '@/styles/globals.css';
import '@near-wallet-selector/modal-ui/styles.css';
import type { AppProps } from 'next/app';
import { useEffect, useState } from 'react';
import { initWalletSelector, getAccounts, initPaymentKey } from '@/lib/near';
import type { AccountState } from '@near-wallet-selector/core';

export default function App({ Component, pageProps }: AppProps) {
  const [accounts, setAccounts] = useState<AccountState[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function init() {
      try {
        // Initialize payment key from localStorage
        initPaymentKey();

        const selector = await initWalletSelector();

        // Subscribe to state changes
        selector.store.observable.subscribe((state) => {
          setAccounts(state.accounts);
        });

        // Get initial accounts
        const initialAccounts = await getAccounts();
        setAccounts(initialAccounts);
      } catch (error) {
        console.error('Failed to initialize wallet:', error);
      } finally {
        setLoading(false);
      }
    }

    init();
  }, []);

  return (
    <Component
      {...pageProps}
      accounts={accounts}
      loading={loading}
    />
  );
}
