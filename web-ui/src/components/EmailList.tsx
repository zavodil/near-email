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
      <div className="p-4 text-center text-gray-500">
        Loading emails...
      </div>
    );
  }

  if (emails.length === 0) {
    return (
      <div className="p-4 text-center text-gray-500">
        No emails yet
      </div>
    );
  }

  return (
    <div>
      {emails.map((email) => (
        <div
          key={email.id}
          onClick={() => onSelect(email)}
          className={`email-item ${selectedId === email.id ? 'bg-blue-50' : ''}`}
        >
          <div className="flex justify-between items-start mb-1">
            <span className="email-from truncate flex-1">{email.from}</span>
            <span className="email-date ml-2">
              {formatDate(email.received_at)}
            </span>
          </div>
          <div className="email-subject truncate">{email.subject || '(no subject)'}</div>
          <div className="email-preview">{getPreview(email.body)}</div>
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
