import type { SentEmail, Attachment } from '@/lib/near';

interface SentEmailViewProps {
  email: SentEmail;
}

export default function SentEmailView({ email }: SentEmailViewProps) {
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
        <h2 className="text-lg font-semibold text-gray-900 leading-tight mb-3">
          {email.subject || '(no subject)'}
        </h2>

        <div className="flex items-center gap-2 text-sm">
          <span className="text-gray-500">To</span>
          <span className="font-medium text-gray-700">{email.to}</span>
          <span className="text-gray-300">|</span>
          <span className="text-gray-400 text-xs">
            {new Date(email.sent_at).toLocaleString()}
          </span>
        </div>

        {email.tx_hash && (
          <div className="text-xs text-gray-400 mt-2 font-mono">
            TX: {email.tx_hash.substring(0, 16)}...
          </div>
        )}
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
