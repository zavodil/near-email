import type { SentEmail } from '@/lib/near';

interface SentEmailViewProps {
  email: SentEmail;
}

export default function SentEmailView({ email }: SentEmailViewProps) {
  return (
    <div className="p-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow p-6 mb-4">
        <h2 className="text-2xl font-semibold text-gray-900 mb-4">
          {email.subject || '(no subject)'}
        </h2>

        <div className="flex items-center text-gray-600 mb-2">
          <span className="font-medium mr-2">To:</span>
          <span>{email.to}</span>
        </div>

        <div className="text-gray-500 text-sm">
          {new Date(email.sent_at).toLocaleString()}
        </div>

        {email.tx_hash && (
          <div className="text-xs text-gray-400 mt-2">
            TX: {email.tx_hash.substring(0, 16)}...
          </div>
        )}
      </div>

      {/* Body */}
      <div className="bg-white rounded-lg shadow p-6">
        <div
          className="prose max-w-none"
          dangerouslySetInnerHTML={{ __html: formatBody(email.body) }}
        />
      </div>
    </div>
  );
}

function formatBody(body: string): string {
  // Basic formatting: convert newlines to <br> if not already HTML
  if (!body.includes('<')) {
    return body.replace(/\r\n/g, '<br>').replace(/\n/g, '<br>');
  }
  return body;
}
