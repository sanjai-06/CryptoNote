import { useState } from "react";

export default function Test2FA() {
  const [showTest, setShowTest] = useState(false);

  if (!showTest) {
    return (
      <div className="fixed bottom-4 left-4 z-50">
        <button
          onClick={() => setShowTest(true)}
          className="px-4 py-2 bg-green-500/80 hover:bg-green-500 backdrop-blur-sm border border-green-400/50 rounded-lg text-white font-semibold transition-all duration-300 transform hover:scale-105 shadow-lg"
        >
          🧪 Test 2FA
        </button>
      </div>
    );
  }

  return (
    <div className="fixed bottom-4 left-4 z-50 bg-gray-900 border border-white/20 rounded-xl p-4 w-80 shadow-2xl">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-white font-semibold">2FA Test Info</h3>
        <button
          onClick={() => setShowTest(false)}
          className="text-gray-400 hover:text-white"
        >
          ✕
        </button>
      </div>
      
      <div className="space-y-3 text-sm">
        <div className="bg-blue-500/20 border border-blue-500/30 rounded-lg p-3">
          <p className="text-blue-300 font-semibold mb-2">Admin Login:</p>
          <p className="text-white">Email: admin@cryptonote.com</p>
          <p className="text-white">Password: Admin@123456</p>
        </div>
        
        <div className="bg-yellow-500/20 border border-yellow-500/30 rounded-lg p-3">
          <p className="text-yellow-300 font-semibold mb-2">Demo Backup Codes:</p>
          <div className="grid grid-cols-1 gap-1 font-mono text-xs">
            <p className="text-white">backup123</p>
            <p className="text-white">backup456</p>
            <p className="text-white">backup789</p>
          </div>
        </div>
        
        <div className="bg-green-500/20 border border-green-500/30 rounded-lg p-3">
          <p className="text-green-300 font-semibold mb-2">Instructions:</p>
          <ol className="text-white text-xs space-y-1">
            <li>1. Login with admin credentials</li>
            <li>2. 2FA modal should appear</li>
            <li>3. Click "Use backup code instead"</li>
            <li>4. Enter: backup123</li>
            <li>5. Should login successfully</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
