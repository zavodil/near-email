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
      <div className="p-8 text-center text-gray-500">
        Loading sent emails...
      </div>
    );
  }

  if (emails.length === 0) {
    return (
      <div className="p-8 text-center text-gray-500">
        No sent emails
      </div>
    );
  }

  return (
    <div>
      {emails.map((email) => (
        <div
          key={email.id}
          onClick={() => onSelect(email)}
          className={`p-4 border-b cursor-pointer hover:bg-gray-50 transition-colors ${
            selectedId === email.id ? 'bg-blue-50' : ''
          }`}
        >
          <div className="flex justify-between items-start mb-1">
            <span className="font-medium text-gray-900 truncate flex-1">
              To: {email.to}
            </span>
            <span className="text-xs text-gray-500 ml-2 whitespace-nowrap">
              {formatDate(email.sent_at)}
            </span>
          </div>
          <div className="text-sm text-gray-700 truncate">
            {email.subject || '(no subject)'}
          </div>
          <div className="text-xs text-gray-500 truncate mt-1">
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
