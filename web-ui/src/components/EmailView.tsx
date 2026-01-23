import { useState } from 'react';
import type { Email } from '@/lib/near';
import { deleteEmail } from '@/lib/near';

interface EmailViewProps {
  email: Email;
  onDelete: () => void;
  onReply: (to: string, subject: string, quotedBody: string) => void;
}

export default function EmailView({ email, onDelete, onReply }: EmailViewProps) {
  const [deleting, setDeleting] = useState(false);

  async function handleDelete() {
    if (!confirm('Delete this email?')) return;

    setDeleting(true);
    try {
      await deleteEmail(email.id);
      onDelete();
    } catch (err) {
      console.error('Failed to delete:', err);
      alert('Failed to delete email');
    } finally {
      setDeleting(false);
    }
  }

  function handleReply() {
    const replyTo = email.from;
    const replySubject = email.subject.startsWith('Re: ')
      ? email.subject
      : `Re: ${email.subject}`;

    // Quote original message
    const date = new Date(email.received_at).toLocaleString();
    const quotedBody = `\n\n-------- Original Message --------\nFrom: ${email.from}\nDate: ${date}\nSubject: ${email.subject}\n\n${email.body}`;

    onReply(replyTo, replySubject, quotedBody);
  }

  return (
    <div className="p-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow p-6 mb-4">
        <div className="flex justify-between items-start mb-4">
          <h2 className="text-2xl font-semibold text-gray-900">
            {email.subject || '(no subject)'}
          </h2>
          <div className="flex gap-3">
            <button
              onClick={handleReply}
              className="text-blue-600 hover:text-blue-700 transition-colors"
            >
              Reply
            </button>
            <button
              onClick={handleDelete}
              disabled={deleting}
              className="text-red-600 hover:text-red-700 transition-colors"
            >
              {deleting ? 'Deleting...' : 'Delete'}
            </button>
          </div>
        </div>

        <div className="flex items-center text-gray-600 mb-2">
          <span className="font-medium mr-2">From:</span>
          <span>{email.from}</span>
        </div>

        <div className="text-gray-500 text-sm">
          {new Date(email.received_at).toLocaleString()}
        </div>
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
    return body.replace(/\n/g, '<br>');
  }
  return body;
}
