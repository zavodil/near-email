import '@/styles/globals.css';
import '@near-wallet-selector/modal-ui/styles.css';
import type { AppProps } from 'next/app';
import Head from 'next/head';
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
    <>
      <Head>
        <link rel="icon" href="/favicon.ico" sizes="any" />
        <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png" />
        <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png" />
        <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
        <link rel="manifest" href="/site.webmanifest" />
        <meta name="theme-color" content="#2563eb" />
      </Head>
      <Component
        {...pageProps}
        accounts={accounts}
        loading={loading}
      />
    </>
  );
}
