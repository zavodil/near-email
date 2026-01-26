import Link from 'next/link';
import Head from 'next/head';

export default function DocsPage() {
  return (
    <>
      <Head>
        <title>How near.email works | Documentation</title>
        <meta name="description" content="Learn how near.email provides secure, private blockchain-based email for NEAR accounts" />
      </Head>

      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100">
        {/* Header */}
        <header className="bg-white/80 backdrop-blur-sm border-b border-gray-100 px-4 py-3 sticky top-0 z-40">
          <div className="max-w-3xl mx-auto flex items-center justify-between">
            <Link href="/" className="text-lg font-semibold text-gray-900 hover:text-blue-600 transition-colors">
              near.email
            </Link>
            <Link
              href="/"
              className="text-sm text-gray-500 hover:text-gray-700 transition-colors"
            >
              Back to app
            </Link>
          </div>
        </header>

        {/* Content */}
        <main className="max-w-3xl mx-auto px-4 py-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            How near.email works
          </h1>
          <p className="text-lg text-gray-500 mb-8">
            Secure, private email for the NEAR ecosystem
          </p>

          {/* Quick Summary */}
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-5 mb-8">
            <h2 className="text-lg font-semibold text-blue-900 mb-3">In Short</h2>
            <ul className="space-y-2 text-blue-800">
              <li className="flex items-start gap-2">
                <span className="text-blue-500 mt-1">&#10003;</span>
                <span>Your emails are <strong>end-to-end encrypted</strong> &mdash; only you can read them</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-500 mt-1">&#10003;</span>
                <span>Your NEAR account is your email: <strong>alice.near = alice@near.email</strong></span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-500 mt-1">&#10003;</span>
                <span>No passwords, no registration &mdash; just connect your wallet</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-blue-500 mt-1">&#10003;</span>
                <span>Server runs in a <strong>Trusted Execution Environment (TEE)</strong> &mdash; even operators can&apos;t access your data</span>
              </li>
            </ul>
          </div>

          {/* Section: What is near.email */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">What is near.email?</h2>
            <p className="text-gray-700 mb-4">
              near.email is a blockchain-native email service for the NEAR ecosystem. Every NEAR account automatically
              has a corresponding email address: if your account is <code className="bg-gray-100 px-1.5 py-0.5 rounded text-sm">alice.near</code>,
              your email is <code className="bg-gray-100 px-1.5 py-0.5 rounded text-sm">alice@near.email</code>.
            </p>
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-3 mb-4 text-sm text-gray-600">
              <strong>New to NEAR?</strong> NEAR blockchain uses human-readable account names like{' '}
              <code className="bg-gray-100 px-1 rounded">alice.near</code> or{' '}
              <code className="bg-gray-100 px-1 rounded">company.near</code> instead of long hex addresses.
              You control your account with a wallet secured by a seed phrase.
            </div>
            <p className="text-gray-700 mb-4">
              You can send and receive emails to/from any regular email address (Gmail, Outlook, etc.) while enjoying
              the security benefits of blockchain-based identity and end-to-end encryption.
            </p>
            <p className="text-gray-700 mb-4">
              near.email is built on{' '}
              <a href="https://outlayer.fastnear.com" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline font-medium">
                NEAR Outlayer
              </a>
              {' '}&mdash; a platform for verifiable off-chain computation with TEE attestation. This means every operation
              is cryptographically proven to run correct code inside a hardware-protected environment.
            </p>
          </section>

          {/* Section: How Security Works */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">How Your Emails Stay Private</h2>

            <div className="space-y-6">
              <div className="bg-white rounded-xl border border-gray-200 p-5">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
                    <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900">End-to-End Encryption</h3>
                </div>
                <p className="text-gray-700 mb-3">
                  Every email is encrypted with a key derived from your NEAR account. When you sign a transaction
                  with your wallet, you prove ownership of your account, and only then can the system decrypt your emails.
                </p>
                <p className="text-gray-600 text-sm">
                  <strong>Technical detail:</strong> We use ECIES (Elliptic Curve Integrated Encryption Scheme) with
                  secp256k1 curves. Each email is encrypted with a unique ephemeral key, and only your account&apos;s
                  derived private key can decrypt it.
                </p>
              </div>

              <div className="bg-white rounded-xl border border-gray-200 p-5">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center">
                    <svg className="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900">Trusted Execution Environment (TEE)</h3>
                </div>
                <p className="text-gray-700 mb-3">
                  The email server runs inside{' '}
                  <a href="https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/tdx-security-research-and-assurance.html" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                    Intel TDX
                  </a>
                  {' '}&mdash; a hardware-isolated environment that even the server operators cannot access.
                  The code running inside is open source and verifiable.
                </p>
                <p className="text-gray-700 mb-3">
                  <strong>Every request is attested:</strong> Each API call returns a cryptographic proof (TEE attestation)
                  that can be independently verified. This proves that the exact published code processed your request
                  inside a secure enclave.
                </p>
                <p className="text-gray-700 mb-3">
                  <strong>To compromise this system, an attacker would need to:</strong> break Intel TDX hardware security
                  (which has been{' '}
                  <a href="https://www.securityweek.com/google-audit-finds-vulnerabilities-in-intel-tdx/" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                    audited by Google
                  </a>{' '}
                  and Microsoft security teams with all found issues patched). No known practical attack exists against
                  current TDX implementations.
                </p>
                <p className="text-gray-600 text-sm">
                  <strong>What this means:</strong> Even if someone gains physical access to the server, they cannot
                  read your emails or extract encryption keys. You can verify the attestation to confirm that untampered
                  code ran your request. Learn more about{' '}
                  <a href="https://outlayer.fastnear.com/docs/tee-attestation" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                    TEE attestation verification
                  </a>.
                </p>
              </div>

              <div className="bg-white rounded-xl border border-gray-200 p-5">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                    <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900">Your Wallet = Your Identity</h3>
                </div>
                <p className="text-gray-700 mb-3">
                  No passwords to remember or leak. Your NEAR wallet cryptographically proves who you are.
                  If you control <code className="bg-gray-100 px-1.5 py-0.5 rounded text-sm">alice.near</code>,
                  you automatically own <code className="bg-gray-100 px-1.5 py-0.5 rounded text-sm">alice@near.email</code>.
                </p>
                <p className="text-gray-600 text-sm">
                  <strong>No phishing risk:</strong> Unlike traditional email where attackers can steal passwords,
                  your NEAR keys stay in your wallet and are never transmitted.
                </p>
              </div>

              <div className="bg-white rounded-xl border border-gray-200 p-5">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 bg-orange-100 rounded-lg flex items-center justify-center">
                    <svg className="w-5 h-5 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-semibold text-gray-900">NEAR MPC Network</h3>
                </div>
                <p className="text-gray-700 mb-3">
                  Encryption keys for your emails are derived using{' '}
                  <a href="https://docs.near.org/chain-abstraction/chain-signatures" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                    NEAR Chain Signatures
                  </a>
                  {' '}&mdash; a decentralized Multi-Party Computation (MPC) network run by{' '}
                  <a href="https://pages.near.org/blog/chain-signatures-launch-to-enable-transactions-on-any-blockchain-from-a-near-account/" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                    independent validators
                  </a>
                  {' '}including Pagoda, Luganodes, and InfStones.
                </p>
                <p className="text-gray-700 mb-3">
                  <strong>No single point of failure:</strong> The full private key never exists in one place. Validators
                  jointly sign using threshold cryptography &mdash; even if some nodes are compromised, the key remains secure.
                  The network is expanding to 40+ nodes with 27 required for any signature.
                </p>
                <p className="text-gray-600 text-sm">
                  <strong>What this means:</strong> To compromise key derivation, an attacker would need to simultaneously
                  compromise a majority of independent, geographically distributed validator nodes &mdash; practically impossible.
                </p>
              </div>
            </div>
          </section>

          {/* Section: What We Can and Cannot See */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">What the Server Can and Cannot See</h2>

            <div className="grid md:grid-cols-2 gap-4">
              <div className="bg-red-50 border border-red-200 rounded-xl p-4">
                <h3 className="font-semibold text-red-900 mb-3 flex items-center gap-2">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                  </svg>
                  Cannot See
                </h3>
                <ul className="space-y-2 text-red-800 text-sm">
                  <li>&#10007; Email content (subject, body)</li>
                  <li>&#10007; Attachments</li>
                  <li>&#10007; Your private keys</li>
                  <li>&#10007; Decrypted data of any kind</li>
                </ul>
              </div>

              <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
                <h3 className="font-semibold text-amber-900 mb-3 flex items-center gap-2">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                  Can See (metadata)
                </h3>
                <ul className="space-y-2 text-amber-800 text-sm">
                  <li>&#10003; Sender/recipient addresses</li>
                  <li>&#10003; Timestamp of emails</li>
                  <li>&#10003; Encrypted blob size</li>
                  <li>&#10003; Your NEAR account ID</li>
                </ul>
              </div>
            </div>

            <p className="text-gray-600 text-sm mt-4">
              <strong>Note:</strong> Metadata visibility is similar to traditional email services. The key difference
              is that your actual email content is always encrypted and inaccessible, even to us.
            </p>
          </section>

          {/* Section: Comparison */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Comparison with Other Email Services</h2>

            <div className="overflow-x-auto">
              <table className="w-full text-sm border border-gray-200 rounded-xl overflow-hidden">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="text-left py-3 px-4 font-medium text-gray-600">Feature</th>
                    <th className="text-center py-3 px-4 font-medium text-gray-600">Gmail</th>
                    <th className="text-center py-3 px-4 font-medium text-gray-600">ProtonMail</th>
                    <th className="text-center py-3 px-4 font-medium text-blue-600">near.email</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  <tr>
                    <td className="py-3 px-4 text-gray-700">Provider can read emails</td>
                    <td className="text-center py-3 px-4 text-red-600">Yes</td>
                    <td className="text-center py-3 px-4 text-yellow-600">With password</td>
                    <td className="text-center py-3 px-4 text-green-600 font-medium">No (TEE)</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 text-gray-700">Password can be stolen</td>
                    <td className="text-center py-3 px-4 text-red-600">Yes</td>
                    <td className="text-center py-3 px-4 text-red-600">Yes</td>
                    <td className="text-center py-3 px-4 text-green-600 font-medium">No password</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 text-gray-700">Verifiable server code</td>
                    <td className="text-center py-3 px-4 text-red-600">No</td>
                    <td className="text-center py-3 px-4 text-red-600">No</td>
                    <td className="text-center py-3 px-4 text-green-600 font-medium">Yes (attestation)</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 text-gray-700">Government subpoena</td>
                    <td className="text-center py-3 px-4 text-red-600">Full access</td>
                    <td className="text-center py-3 px-4 text-yellow-600">Encrypted</td>
                    <td className="text-center py-3 px-4 text-green-600 font-medium">Encrypted</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 text-gray-700">Account recovery</td>
                    <td className="text-center py-3 px-4 text-gray-600">Phone/email</td>
                    <td className="text-center py-3 px-4 text-gray-600">Recovery phrase</td>
                    <td className="text-center py-3 px-4 text-gray-600">Wallet seed</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 text-gray-700">Send to regular email</td>
                    <td className="text-center py-3 px-4 text-green-600">Yes</td>
                    <td className="text-center py-3 px-4 text-green-600">Yes</td>
                    <td className="text-center py-3 px-4 text-green-600">Yes</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="text-gray-500 text-sm mt-3">
              <strong>Key difference from ProtonMail:</strong> ProtonMail encrypts your emails, but you must trust that their servers
              do what they claim. near.email uses TEE attestation &mdash; you can cryptographically verify that the correct code ran.
            </p>
          </section>

          {/* Section: How It Works Technically */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Technical Flow</h2>

            <div className="space-y-4">
              <div className="flex gap-4">
                <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 font-bold flex-shrink-0">1</div>
                <div>
                  <h3 className="font-semibold text-gray-900">Receiving External Email</h3>
                  <p className="text-gray-600 text-sm">
                    When someone sends email to alice@near.email from Gmail/Outlook, our SMTP server receives it inside the TEE,
                    <strong> immediately encrypts it</strong> with alice.near&apos;s public key, stores only the encrypted blob,
                    and <strong>deletes the original</strong>. The plaintext email never touches persistent storage.
                  </p>
                </div>
              </div>

              <div className="flex gap-4">
                <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 font-bold flex-shrink-0">2</div>
                <div>
                  <h3 className="font-semibold text-gray-900">Sending Email</h3>
                  <p className="text-gray-600 text-sm">
                    You compose an email normally. If the recipient is a NEAR account (bob@near.email), the email
                    is encrypted and stored directly &mdash; <strong>no external servers involved</strong>, no trace left outside.
                    If sending to Gmail/Outlook, the TEE sends it via SMTP and keeps an encrypted copy in your Sent folder.
                  </p>
                </div>
              </div>

              <div className="flex gap-4">
                <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 font-bold flex-shrink-0">3</div>
                <div>
                  <h3 className="font-semibold text-gray-900">Reading Email</h3>
                  <p className="text-gray-600 text-sm">
                    When you connect your wallet and request emails, you sign a message proving you own your account.
                    The TEE decrypts emails using your derived key and re-encrypts them for secure transmission to your browser.
                    <strong> Without your NEAR account, no one can access your emails</strong> &mdash; not even us.
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-xl">
              <p className="text-green-800 text-sm">
                <strong>Key point:</strong> The server only stores encrypted data. If the database is stolen, attackers get useless encrypted blobs.
                Only your NEAR wallet can decrypt your emails.
              </p>
            </div>
          </section>

          {/* Section: Size Limits */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Size Limits</h2>
            <p className="text-gray-700 mb-4">
              Due to blockchain and encryption overhead, there are limits on email and attachment sizes:
            </p>

            <div className="overflow-x-auto">
              <table className="w-full text-sm border border-gray-200 rounded-xl overflow-hidden">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="text-left py-3 px-4 font-medium text-gray-600">Limit</th>
                    <th className="text-center py-3 px-4 font-medium text-gray-600">Blockchain Mode</th>
                    <th className="text-center py-3 px-4 font-medium text-green-600">HTTPS Mode</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  <tr>
                    <td className="py-3 px-4 text-gray-700">Send: per file</td>
                    <td className="text-center py-3 px-4 text-gray-600">5 MB</td>
                    <td className="text-center py-3 px-4 text-gray-600">5 MB</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 text-gray-700">Send: total</td>
                    <td className="text-center py-3 px-4 text-gray-600">7 MB</td>
                    <td className="text-center py-3 px-4 text-gray-600">7 MB</td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 text-gray-700">Download attachment</td>
                    <td className="text-center py-3 px-4 text-blue-600">1.1 MB</td>
                    <td className="text-center py-3 px-4 text-green-600 font-medium">18 MB</td>
                  </tr>
                  <tr className="bg-gray-50/50">
                    <td className="py-3 px-4 text-gray-700">Max response size</td>
                    <td className="text-center py-3 px-4 text-blue-600">1.5 MB</td>
                    <td className="text-center py-3 px-4 text-green-600 font-medium">25 MB</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-xl">
              <p className="text-green-800 text-sm">
                <strong>HTTPS Mode</strong> uses a Payment Key from{' '}
                <a href="https://outlayer.fastnear.com" target="_blank" rel="noopener noreferrer" className="underline">
                  OutLayer Dashboard
                </a>{' '}
                for higher limits. It&apos;s faster and supports larger attachments while maintaining the same security guarantees.
              </p>
            </div>
          </section>

          {/* Section: Payment Keys */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Payment Keys: Alternative Access Method</h2>
            <p className="text-gray-700 mb-4">
              near.email supports two access methods with <strong>identical security guarantees</strong>. Both use the same
              TEE-protected code and encryption. The difference is how you authenticate and pay.
            </p>

            <div className="grid md:grid-cols-2 gap-4 mb-6">
              <div className="bg-gray-50 border border-gray-200 rounded-xl p-4">
                <h3 className="font-semibold text-gray-700 mb-2">Blockchain Mode</h3>
                <ul className="space-y-1 text-gray-600 text-sm">
                  <li>&bull; Sign each request with wallet</li>
                  <li>&bull; Pay gas fees per transaction</li>
                  <li>&bull; Max 1.1 MB attachment download</li>
                  <li>&bull; No prepayment needed</li>
                </ul>
              </div>
              <div className="bg-green-50 border border-green-200 rounded-xl p-4">
                <h3 className="font-semibold text-green-700 mb-2">HTTPS Mode (Payment Key)</h3>
                <ul className="space-y-1 text-green-700 text-sm">
                  <li>&bull; No wallet popups needed</li>
                  <li>&bull; Prepaid USD balance (cheaper)</li>
                  <li>&bull; Max 18 MB attachment download</li>
                  <li>&bull; Same TEE security</li>
                </ul>
              </div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 p-5">
              <h3 className="font-semibold text-gray-900 mb-3">How to Get a Payment Key</h3>
              <ol className="space-y-2 text-gray-700 text-sm">
                <li className="flex gap-3">
                  <span className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 font-medium flex-shrink-0">1</span>
                  <span>
                    Go to{' '}
                    <a href="https://outlayer.fastnear.com/payment-keys" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                      OutLayer Dashboard → Payment Keys
                    </a>
                  </span>
                </li>
                <li className="flex gap-3">
                  <span className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 font-medium flex-shrink-0">2</span>
                  <span>Create a new key and add USD balance (minimum $0.10)</span>
                </li>
                <li className="flex gap-3">
                  <span className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 font-medium flex-shrink-0">3</span>
                  <span>Copy the key (format: <code className="bg-gray-100 px-1 rounded">owner:nonce:secret</code>)</span>
                </li>
                <li className="flex gap-3">
                  <span className="w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 font-medium flex-shrink-0">4</span>
                  <span>In near.email, click your avatar → Configure Payment Key → Paste and save</span>
                </li>
              </ol>
              <p className="text-gray-500 text-xs mt-4">
                Typical cost: ~$0.001 per email operation. A $1 balance lasts for hundreds of emails.
              </p>
            </div>
          </section>

          {/* Section: FAQ */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Frequently Asked Questions</h2>

            <div className="space-y-4">
              <details className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                <summary className="px-5 py-4 cursor-pointer font-medium text-gray-900 hover:bg-gray-50">
                  Can you read my emails?
                </summary>
                <div className="px-5 pb-4 text-gray-600 text-sm">
                  No. Emails are encrypted before storage, and the encryption keys are derived inside a TEE
                  that we cannot access. Even with full database access, we would only see encrypted blobs.
                </div>
              </details>

              <details className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                <summary className="px-5 py-4 cursor-pointer font-medium text-gray-900 hover:bg-gray-50">
                  What if I lose access to my NEAR account?
                </summary>
                <div className="px-5 pb-4 text-gray-600 text-sm">
                  Your emails can only be decrypted with your NEAR account keys. If you lose your seed phrase,
                  you lose access to your emails permanently. This is the tradeoff for true ownership &mdash;
                  no &quot;forgot password&quot; recovery exists.
                </div>
              </details>

              <details className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                <summary className="px-5 py-4 cursor-pointer font-medium text-gray-900 hover:bg-gray-50">
                  Can governments force you to hand over my emails?
                </summary>
                <div className="px-5 pb-4 text-gray-600 text-sm">
                  We can only provide encrypted data &mdash; the same data any attacker would get in a breach.
                  Without your NEAR private key, the emails cannot be decrypted. We literally cannot comply
                  with decryption requests even if we wanted to.
                </div>
              </details>

              <details className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                <summary className="px-5 py-4 cursor-pointer font-medium text-gray-900 hover:bg-gray-50">
                  Is the code open source?
                </summary>
                <div className="px-5 pb-4 text-gray-600 text-sm">
                  Yes. The WASI module running inside the TEE is open source and can be verified.
                  The TEE provides attestation proving that the published code is what&apos;s actually running.
                </div>
              </details>

              <details className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                <summary className="px-5 py-4 cursor-pointer font-medium text-gray-900 hover:bg-gray-50">
                  Can I send emails to regular email addresses?
                </summary>
                <div className="px-5 pb-4 text-gray-600 text-sm">
                  Yes. You can send to and receive from any email address (Gmail, Outlook, etc.).
                  Emails to external addresses are sent via standard SMTP. Emails stored on our side
                  remain encrypted.
                </div>
              </details>

              <details className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                <summary className="px-5 py-4 cursor-pointer font-medium text-gray-900 hover:bg-gray-50">
                  Is it free? How much does it cost?
                </summary>
                <div className="px-5 pb-4 text-gray-600 text-sm">
                  <strong>Blockchain mode:</strong> You pay NEAR gas fees (~0.001 NEAR per operation, fractions of a cent).
                  <br /><br />
                  <strong>HTTPS mode (Payment Key):</strong> ~$0.001 per operation from your prepaid USD balance. A $1 balance
                  lasts for hundreds of emails.
                  <br /><br />
                  There are no subscription fees or monthly charges.
                </div>
              </details>

              <details className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                <summary className="px-5 py-4 cursor-pointer font-medium text-gray-900 hover:bg-gray-50">
                  What is a Payment Key?
                </summary>
                <div className="px-5 pb-4 text-gray-600 text-sm">
                  A Payment Key is a prepaid API key that allows you to use HTTPS mode instead of blockchain transactions.
                  Benefits: no wallet popups, larger attachment downloads (18 MB vs 1.1 MB), cheaper than gas fees.
                  Same security guarantees as blockchain mode. Create one at{' '}
                  <a href="https://outlayer.fastnear.com/payment-keys" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                    OutLayer Dashboard
                  </a>. Typical cost is ~$0.001 per operation.
                </div>
              </details>

              <details className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                <summary className="px-5 py-4 cursor-pointer font-medium text-gray-900 hover:bg-gray-50">
                  How can I verify that the code is really secure?
                </summary>
                <div className="px-5 pb-4 text-gray-600 text-sm">
                  Every request returns a TEE attestation &mdash; a cryptographic proof from Intel hardware that specific code
                  ran inside a secure enclave. You can verify this attestation independently using{' '}
                  <a href="https://outlayer.fastnear.com/docs/tee-attestation" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                    our verification guide
                  </a>. The WASI module source code is open source and the attestation proves that exact code (by hash)
                  processed your request.
                </div>
              </details>

              <details className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                <summary className="px-5 py-4 cursor-pointer font-medium text-gray-900 hover:bg-gray-50">
                  What is NEAR Outlayer?
                </summary>
                <div className="px-5 pb-4 text-gray-600 text-sm">
                  <a href="https://outlayer.fastnear.com" target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                    NEAR Outlayer
                  </a>{' '}
                  is the platform that powers near.email. It provides verifiable off-chain computation with TEE attestation
                  for the NEAR ecosystem. Developers can build secure applications where users can cryptographically verify
                  what code ran on their data.
                </div>
              </details>

              <details className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                <summary className="px-5 py-4 cursor-pointer font-medium text-gray-900 hover:bg-gray-50">
                  How is this different from ProtonMail?
                </summary>
                <div className="px-5 pb-4 text-gray-600 text-sm">
                  Both encrypt your emails, but the trust model differs:
                  <br /><br />
                  <strong>ProtonMail:</strong> You trust that their servers run the code they claim. There&apos;s no way to independently verify this.
                  <br /><br />
                  <strong>near.email:</strong> Server runs in a hardware-protected TEE (Intel TDX). Every request returns a cryptographic attestation
                  proving exactly what code ran. You can verify this independently &mdash; no trust required.
                  <br /><br />
                  Additionally, near.email uses your blockchain wallet instead of a password, eliminating phishing and credential theft risks.
                </div>
              </details>
            </div>
          </section>

          {/* Section: Trust Model */}
          <section className="mb-10">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Trust Model Summary</h2>

            <div className="bg-gray-50 border border-gray-200 rounded-xl p-5 mb-4">
              <p className="text-gray-700 mb-4">
                With near.email, you trust:
              </p>
              <ul className="space-y-3 text-gray-700">
                <li className="flex items-start gap-3">
                  <span className="text-green-500 mt-1">&#10003;</span>
                  <span><strong>Intel TDX hardware</strong> &mdash; that it correctly isolates the TEE (audited by Google &amp; Microsoft)</span>
                </li>
                <li className="flex items-start gap-3">
                  <span className="text-green-500 mt-1">&#10003;</span>
                  <span><strong>NEAR MPC Network</strong> &mdash; independent validators for key derivation</span>
                </li>
                <li className="flex items-start gap-3">
                  <span className="text-green-500 mt-1">&#10003;</span>
                  <span><strong>Open source code</strong> &mdash; which you can audit and verify via attestation</span>
                </li>
                <li className="flex items-start gap-3">
                  <span className="text-green-500 mt-1">&#10003;</span>
                  <span><strong>Standard cryptography</strong> &mdash; ECIES, AES-GCM (widely audited algorithms)</span>
                </li>
              </ul>
              <p className="text-gray-600 text-sm mt-4">
                You do <strong>not</strong> need to trust the operators, hosting provider, or database administrators.
              </p>
            </div>

            <div className="bg-red-50 border border-red-200 rounded-xl p-5">
              <h3 className="font-semibold text-red-900 mb-3">What would it take to compromise near.email?</h3>
              <p className="text-red-800 text-sm mb-3">
                An attacker would need to accomplish <strong>at least one</strong> of these extremely difficult tasks:
              </p>
              <ul className="space-y-2 text-red-800 text-sm">
                <li className="flex items-start gap-2">
                  <span>&#10007;</span>
                  <span><strong>Break Intel TDX</strong> &mdash; no known practical attack exists; all found vulnerabilities have been patched</span>
                </li>
                <li className="flex items-start gap-2">
                  <span>&#10007;</span>
                  <span><strong>Compromise 27+ of 40 MPC validators</strong> &mdash; simultaneously, across independent organizations worldwide</span>
                </li>
                <li className="flex items-start gap-2">
                  <span>&#10007;</span>
                  <span><strong>Break ECIES/secp256k1 cryptography</strong> &mdash; would require breaking Bitcoin&apos;s security too</span>
                </li>
                <li className="flex items-start gap-2">
                  <span>&#10007;</span>
                  <span><strong>Steal your NEAR wallet keys</strong> &mdash; but that&apos;s your responsibility, not ours</span>
                </li>
              </ul>
            </div>
          </section>

          {/* Back to app */}
          <div className="text-center pt-6 border-t border-gray-200">
            <Link
              href="/"
              className="inline-flex items-center gap-2 bg-blue-600 text-white px-6 py-2.5 rounded-xl font-medium hover:bg-blue-700 transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              Go to near.email
            </Link>
            <p className="text-gray-400 text-sm mt-4">
              Powered by{' '}
              <a href="https://outlayer.fastnear.com" target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline">NEAR Outlayer</a>
            </p>
          </div>
        </main>
      </div>
    </>
  );
}
