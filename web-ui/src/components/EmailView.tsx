import { useState } from 'react';
import type { Email, Attachment } from '@/lib/near';
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

  function downloadAttachment(att: Attachment) {
    // Decode base64 to binary
    const binary = atob(att.data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const blob = new Blob([bytes], { type: att.content_type });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = att.filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  const attachments = email.attachments || [];

  return (
    <div className="p-4">
      {/* Header */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4 mb-3">
        <div className="flex justify-between items-start gap-3 mb-3">
          <h2 className="text-lg font-semibold text-gray-900 leading-tight">
            {email.subject || '(no subject)'}
          </h2>
          <div className="flex gap-1.5 flex-shrink-0">
            <button
              onClick={handleReply}
              className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-md transition-colors"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6" />
              </svg>
              Reply
            </button>
            <button
              onClick={handleDelete}
              disabled={deleting}
              className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded-md transition-colors disabled:opacity-50"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
              {deleting ? '...' : 'Delete'}
            </button>
          </div>
        </div>

        <div className="flex items-center gap-2 text-sm">
          <span className="text-gray-500">From</span>
          <span className="font-medium text-gray-700">{email.from}</span>
          <span className="text-gray-300">|</span>
          <span className="text-gray-400 text-xs">
            {new Date(email.received_at).toLocaleString()}
          </span>
        </div>
      </div>

      {/* Attachments */}
      {attachments.length > 0 && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-3 mb-3">
          <h3 className="text-xs font-medium text-gray-500 mb-2">
            {attachments.length} {attachments.length === 1 ? 'attachment' : 'attachments'}
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {attachments.map((att, idx) => (
              <button
                key={idx}
                onClick={() => downloadAttachment(att)}
                className="flex items-center gap-1.5 px-2.5 py-1.5 bg-gray-50 hover:bg-gray-100 rounded-md transition-colors text-xs border border-gray-200"
              >
                <svg className="w-3.5 h-3.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                <span className="text-gray-700 max-w-[150px] truncate">{att.filename}</span>
                <span className="text-gray-400">({formatSize(att.size)})</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Body */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
        <div
          className="prose prose-sm max-w-none text-gray-700"
          dangerouslySetInnerHTML={{ __html: formatBody(email.body) }}
        />
      </div>
    </div>
  );
}

function formatBody(body: string): string {
  // Check if it's plain text (not HTML)
  if (!body.includes('<')) {
    // Split by "-------- Original Message --------" to style quoted content
    const parts = body.split(/(-{4,}\s*Original Message\s*-{4,})/i);

    if (parts.length > 1) {
      // First part is the new message
      const mainMessage = parts[0].replace(/\r\n/g, '<br>').replace(/\n/g, '<br>');
      // Rest is quoted content (delimiter + quoted text)
      const quotedParts = parts.slice(1).join('');
      const quotedMessage = quotedParts.replace(/\r\n/g, '<br>').replace(/\n/g, '<br>');

      return `${mainMessage}<div class="mt-4 pt-4 border-t border-gray-200 text-gray-500 text-sm">${quotedMessage}</div>`;
    }

    // No quote delimiter found, just convert newlines
    return body.replace(/\r\n/g, '<br>').replace(/\n/g, '<br>');
  }
  return body;
}
