interface LimitsModalProps {
  isOpen: boolean;
  onClose: () => void;
  isHttpsMode: boolean;
}

export default function LimitsModal({ isOpen, onClose, isHttpsMode }: LimitsModalProps) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-2xl shadow-2xl max-w-lg w-full p-6">
        {/* Header */}
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold text-gray-900">Size Limits</h2>
          <button
            onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-md transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Current mode indicator */}
        <div className={`p-3 rounded-lg mb-4 ${isHttpsMode ? 'bg-green-50 border border-green-200' : 'bg-blue-50 border border-blue-200'}`}>
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${isHttpsMode ? 'bg-green-500' : 'bg-blue-500'}`} />
            <span className="font-medium text-gray-700">Current mode: </span>
            {isHttpsMode ? (
              <span className="text-green-700 font-medium">HTTPS (Payment Key) - Higher limits</span>
            ) : (
              <span className="text-blue-700 font-medium">Blockchain - Standard limits</span>
            )}
          </div>
        </div>

        {/* Limits table */}
        <div className="overflow-hidden rounded-lg border border-gray-200">
          <table className="w-full text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="text-left py-2.5 px-3 font-medium text-gray-600">Limit</th>
                <th className="text-center py-2.5 px-3 font-medium text-blue-600">Blockchain</th>
                <th className="text-center py-2.5 px-3 font-medium text-green-600">HTTPS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              <tr className={!isHttpsMode ? 'bg-blue-50/30' : ''}>
                <td className="py-2.5 px-3 text-gray-700">Send: per file</td>
                <td className="text-center py-2.5 px-3 text-gray-600">5 MB</td>
                <td className="text-center py-2.5 px-3 text-gray-600">5 MB</td>
              </tr>
              <tr className={!isHttpsMode ? 'bg-blue-50/30' : ''}>
                <td className="py-2.5 px-3 text-gray-700">Send: total</td>
                <td className="text-center py-2.5 px-3 text-gray-600">7 MB</td>
                <td className="text-center py-2.5 px-3 text-gray-600">7 MB</td>
              </tr>
              <tr className={!isHttpsMode ? 'bg-blue-50/30' : 'bg-green-50/30'}>
                <td className="py-2.5 px-3 text-gray-700 font-medium">Download attachment</td>
                <td className="text-center py-2.5 px-3 text-blue-600 font-medium">1.1 MB</td>
                <td className="text-center py-2.5 px-3 text-green-600 font-semibold">18 MB</td>
              </tr>
              <tr className={!isHttpsMode ? 'bg-blue-50/30' : 'bg-green-50/30'}>
                <td className="py-2.5 px-3 text-gray-700">Max response</td>
                <td className="text-center py-2.5 px-3 text-blue-600">1.5 MB</td>
                <td className="text-center py-2.5 px-3 text-green-600 font-medium">25 MB</td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Upgrade hint */}
        {!isHttpsMode && (
          <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
            <div className="flex items-start gap-2">
              <svg className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div className="text-sm text-yellow-800">
                <strong>Tip:</strong> Connect with a Payment Key to unlock higher download limits (18 MB vs 1.1 MB for attachments).
              </div>
            </div>
          </div>
        )}

        {isHttpsMode && (
          <div className="mt-4 p-3 bg-green-50 border border-green-200 rounded-lg">
            <div className="flex items-start gap-2">
              <svg className="w-5 h-5 text-green-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div className="text-sm text-green-800">
                You&apos;re using Payment Key mode with higher limits for downloading large attachments.
              </div>
            </div>
          </div>
        )}

        {/* Close button */}
        <button
          onClick={onClose}
          className="mt-4 w-full py-2.5 bg-gray-100 hover:bg-gray-200 text-gray-700 font-medium rounded-lg transition-colors"
        >
          Close
        </button>
      </div>
    </div>
  );
}
