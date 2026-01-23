import type { SentEmail } from '@/lib/near';

interface SentEmailListProps {
  emails: SentEmail[];
  selectedId?: string;
  onSelect: (email: SentEmail) => void;
  loading: boolean;
}

export default function SentEmailList({ emails, selectedId, onSelect, loading }: SentEmailListProps) {
  if (loading && emails.length === 0) {
    return (
      <div className="p-6 text-center">
        <div className="inline-block w-5 h-5 border-2 border-gray-200 border-t-blue-500 rounded-full animate-spin mb-2"></div>
        <p className="text-sm text-gray-400">Loading sent emails...</p>
      </div>
    );
  }

  if (emails.length === 0) {
    return (
      <div className="p-6 text-center">
        <svg className="w-10 h-10 mx-auto text-gray-200 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
        </svg>
        <p className="text-sm text-gray-400">No sent emails</p>
      </div>
    );
  }

  return (
    <div className="divide-y divide-gray-100">
      {emails.map((email) => (
        <div
          key={email.id}
          onClick={() => onSelect(email)}
          className={`px-3 py-2.5 cursor-pointer transition-colors ${
            selectedId === email.id
              ? 'bg-blue-50 border-l-2 border-blue-500'
              : 'hover:bg-gray-50 border-l-2 border-transparent'
          }`}
        >
          <div className="flex justify-between items-center gap-2 mb-0.5">
            <span className="text-sm font-medium text-gray-800 truncate">
              To: {email.to}
            </span>
            <span className="text-xs text-gray-400 flex-shrink-0">
              {formatDate(email.sent_at)}
            </span>
          </div>
          <div className="text-sm text-gray-700 truncate mb-0.5">
            {email.subject || '(no subject)'}
          </div>
          <div className="text-xs text-gray-400 truncate">
            {email.body.substring(0, 100)}
          </div>
        </div>
      ))}
    </div>
  );
}

function formatDate(isoDate: string): string {
  const date = new Date(isoDate);
  const now = new Date();
  const isToday = date.toDateString() === now.toDateString();

  if (isToday) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
}
