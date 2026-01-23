import type { Email } from '@/lib/near';

interface EmailListProps {
  emails: Email[];
  selectedId?: string;
  onSelect: (email: Email) => void;
  loading: boolean;
}

export default function EmailList({ emails, selectedId, onSelect, loading }: EmailListProps) {
  if (loading) {
    return (
      <div className="p-6 text-center">
        <div className="inline-block w-5 h-5 border-2 border-gray-200 border-t-blue-500 rounded-full animate-spin mb-2"></div>
        <p className="text-sm text-gray-400">Loading emails...</p>
      </div>
    );
  }

  if (emails.length === 0) {
    return (
      <div className="p-6 text-center">
        <svg className="w-10 h-10 mx-auto text-gray-200 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
        <p className="text-sm text-gray-400">No emails yet</p>
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
            <span className="text-sm font-medium text-gray-800 truncate">{email.from}</span>
            <span className="text-xs text-gray-400 flex-shrink-0">
              {formatDate(email.received_at)}
            </span>
          </div>
          <div className="text-sm text-gray-700 truncate mb-0.5">{email.subject || '(no subject)'}</div>
          <div className="text-xs text-gray-400 truncate">{getPreview(email.body)}</div>
        </div>
      ))}
    </div>
  );
}

function formatDate(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - date.getTime();

  // Today
  if (diff < 24 * 60 * 60 * 1000 && date.getDate() === now.getDate()) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  // This year
  if (date.getFullYear() === now.getFullYear()) {
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  }

  // Older
  return date.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
}

function getPreview(body: string): string {
  // Strip HTML tags and get first 100 chars
  const text = body.replace(/<[^>]*>/g, '').trim();
  return text.length > 100 ? text.substring(0, 100) + '...' : text;
}
