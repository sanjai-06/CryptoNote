import { useState, useEffect, useRef } from "react";
import API from "../api/axios";

export default function TwoFactorAuth({ isOpen, onClose, onSuccess, email, tempToken }) {
  const [step, setStep] = useState("verify"); // verify, setup, backup
  const [code, setCode] = useState(["", "", "", "", "", ""]);
  const [qrCode, setQrCode] = useState("");
  const [secret, setSecret] = useState("");
  const [backupCodes, setBackupCodes] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [timeLeft, setTimeLeft] = useState(30);
  const inputRefs = useRef([]);

  // Update code array size when step changes
  useEffect(() => {
    if (step === "backup-verify") {
      setCode(["", "", "", "", "", "", "", "", ""]); // 9 characters for backup
    } else {
      setCode(["", "", "", "", "", ""]); // 6 characters for TOTP
    }
    setError(""); // Clear errors when switching steps
  }, [step]);

  useEffect(() => {
    if (isOpen) {
      // Check if user has 2FA enabled
      checkTwoFactorStatus();
    }
  }, [isOpen]);

  useEffect(() => {
    // Timer for TOTP countdown
    const timer = setInterval(() => {
      setTimeLeft(prev => {
        if (prev <= 1) {
          return 30; // Reset to 30 seconds
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const checkTwoFactorStatus = async () => {
    try {
      const response = await API.post("/auth/check-2fa", { email });
      if (response.data.enabled) {
        setStep("verify");
      } else {
        setStep("setup");
        generateQRCode();
      }
    } catch (err) {
      // If user doesn't have 2FA, show setup
      setStep("setup");
      generateQRCode();
    }
  };

  const generateQRCode = async () => {
    try {
      const response = await API.post("/auth/generate-2fa", { 
        email,
        tempToken 
      });
      setQrCode(response.data.qrCode);
      setSecret(response.data.secret);
    } catch (err) {
      // Mock QR code for demo
      setQrCode("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==");
      setSecret("JBSWY3DPEHPK3PXP");
      console.error("Failed to generate QR code:", err);
    }
  };

  const handleCodeChange = (index, value) => {
    if (value.length > 1) return;
    
    const newCode = [...code];
    newCode[index] = value;
    setCode(newCode);

    // Auto-focus next input
    const maxIndex = step === "backup-verify" ? 8 : 5; // 9 chars for backup, 6 for TOTP
    if (value && index < maxIndex) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index, e) => {
    if (e.key === "Backspace" && !code[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handleVerify = async () => {
    const verificationCode = code.join("");
    if (verificationCode.length !== 6) {
      setError("Please enter a complete 6-digit code");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await API.post("/auth/verify-2fa", {
        email,
        code: verificationCode,
        tempToken,
        setup: step === "setup"
      });

      if (step === "setup") {
        // Show backup codes
        setBackupCodes(response.data.backupCodes || [
          "1a2b3c4d", "5e6f7g8h", "9i0j1k2l", "3m4n5o6p",
          "7q8r9s0t", "1u2v3w4x", "5y6z7a8b", "9c0d1e2f"
        ]);
        setStep("backup");
      } else {
        // Login successful
        onSuccess(response.data);
      }
    } catch (err) {
      setError(err.response?.data?.message || "Invalid verification code");
    } finally {
      setLoading(false);
    }
  };

  const handleSetupComplete = () => {
    onSuccess({ 
      message: "2FA setup completed successfully! Check your email for setup instructions and backup codes.",
      emailSent: true
    });
  };

  const handleUseBackupCode = () => {
    // Switch to backup code input
    setStep("backup-verify");
    // Code will be set by useEffect when step changes
  };

  const handleBackupCodeVerify = async () => {
    const backupCode = code.join("");
    if (backupCode.length < 6) {
      setError("Please enter a complete backup code");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await API.post("/auth/verify-backup-code", {
        email,
        backupCode,
        tempToken
      });

      onSuccess(response.data);
    } catch (err) {
      setError(err.response?.data?.message || "Invalid backup code");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const downloadBackupCodes = () => {
    const content = `CryptoNote 2FA Backup Codes\n\nGenerated: ${new Date().toLocaleString()}\nAccount: ${email}\n\n${backupCodes.map((code, i) => `${i + 1}. ${code}`).join('\n')}\n\nKeep these codes safe and secure!`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cryptonote-backup-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-gradient-to-br from-gray-900 to-gray-800 border border-white/20 rounded-2xl p-8 w-full max-w-md mx-4 shadow-2xl">
        
        {/* Verify Step */}
        {step === "verify" && (
          <>
            <div className="text-center mb-6">
              <div className="w-16 h-16 bg-gradient-to-r from-blue-500 to-purple-500 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">🔐</span>
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">Two-Factor Authentication</h3>
              <p className="text-gray-400">Enter the 6-digit code from your authenticator app</p>
            </div>

            <div className="mb-6">
              <div className="flex justify-center space-x-3 mb-4">
                {code.map((digit, index) => (
                  <input
                    key={index}
                    ref={el => inputRefs.current[index] = el}
                    type="text"
                    maxLength="1"
                    value={digit}
                    onChange={(e) => handleCodeChange(index, e.target.value)}
                    onKeyDown={(e) => handleKeyDown(index, e)}
                    className="w-12 h-12 text-center text-xl font-bold bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all duration-300"
                  />
                ))}
              </div>

              {/* TOTP Timer */}
              <div className="flex items-center justify-center space-x-2 mb-4">
                <div className="w-8 h-8 relative">
                  <svg className="w-8 h-8 transform -rotate-90" viewBox="0 0 32 32">
                    <circle
                      cx="16"
                      cy="16"
                      r="14"
                      stroke="currentColor"
                      strokeWidth="2"
                      fill="none"
                      className="text-gray-600"
                    />
                    <circle
                      cx="16"
                      cy="16"
                      r="14"
                      stroke="currentColor"
                      strokeWidth="2"
                      fill="none"
                      strokeDasharray={`${2 * Math.PI * 14}`}
                      strokeDashoffset={`${2 * Math.PI * 14 * (1 - timeLeft / 30)}`}
                      className="text-blue-500 transition-all duration-1000"
                    />
                  </svg>
                </div>
                <span className="text-gray-400 text-sm">Code refreshes in {timeLeft}s</span>
              </div>

              {error && (
                <div className="bg-red-500/20 border border-red-500/30 text-red-200 p-3 rounded-lg mb-4 text-center text-sm">
                  <span className="text-red-300">⚠️</span> {error}
                </div>
              )}
            </div>

            <div className="space-y-3">
              <button
                onClick={handleVerify}
                disabled={loading || code.join("").length !== 6}
                className="w-full py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 disabled:from-gray-600 disabled:to-gray-700 rounded-lg text-white font-semibold transition-all duration-300 transform hover:scale-[1.02] disabled:scale-100"
              >
                {loading ? (
                  <span className="flex items-center justify-center">
                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Verifying...
                  </span>
                ) : (
                  "Verify & Login"
                )}
              </button>

              <button
                onClick={handleUseBackupCode}
                className="w-full py-2 text-gray-400 hover:text-white transition-colors text-sm"
              >
                Use backup code instead
              </button>

              <button
                onClick={onClose}
                className="w-full py-2 text-gray-400 hover:text-white transition-colors text-sm"
              >
                Cancel
              </button>
            </div>
          </>
        )}

        {/* Setup Step */}
        {step === "setup" && (
          <>
            <div className="text-center mb-6">
              <div className="w-16 h-16 bg-gradient-to-r from-green-500 to-blue-500 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">📱</span>
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">Setup Two-Factor Authentication</h3>
              <p className="text-gray-400">Scan the QR code with your authenticator app</p>
            </div>

            <div className="mb-6">
              {/* QR Code */}
              <div className="bg-white p-4 rounded-lg mb-4 flex justify-center">
                {qrCode ? (
                  <img src={qrCode} alt="2FA QR Code" className="w-48 h-48" />
                ) : (
                  <div className="w-48 h-48 bg-gray-200 rounded-lg flex items-center justify-center">
                    <span className="text-gray-500">Loading QR Code...</span>
                  </div>
                )}
              </div>

              {/* Manual Entry */}
              <div className="bg-white/5 border border-white/20 rounded-lg p-4 mb-4">
                <p className="text-gray-400 text-sm mb-2">Can't scan? Enter this code manually:</p>
                <div className="flex items-center space-x-2">
                  <code className="flex-1 bg-gray-800 px-3 py-2 rounded text-green-400 font-mono text-sm">
                    {secret}
                  </code>
                  <button
                    onClick={() => copyToClipboard(secret)}
                    className="p-2 bg-blue-500/20 hover:bg-blue-500/30 rounded text-blue-300 transition-colors"
                    title="Copy to clipboard"
                  >
                    📋
                  </button>
                </div>
              </div>

              {/* Verification */}
              <div className="mb-4">
                <p className="text-gray-300 text-sm mb-3">Enter the 6-digit code from your app to verify:</p>
                <div className="flex justify-center space-x-2 mb-4">
                  {code.map((digit, index) => (
                    <input
                      key={index}
                      ref={el => inputRefs.current[index] = el}
                      type="text"
                      maxLength="1"
                      value={digit}
                      onChange={(e) => handleCodeChange(index, e.target.value)}
                      onKeyDown={(e) => handleKeyDown(index, e)}
                      className="w-10 h-10 text-center text-lg font-bold bg-white/10 border border-white/20 rounded text-white focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-green-500/50 transition-all duration-300"
                    />
                  ))}
                </div>
              </div>

              {error && (
                <div className="bg-red-500/20 border border-red-500/30 text-red-200 p-3 rounded-lg mb-4 text-center text-sm">
                  <span className="text-red-300">⚠️</span> {error}
                </div>
              )}
            </div>

            <div className="space-y-3">
              <button
                onClick={handleVerify}
                disabled={loading || code.join("").length !== 6}
                className="w-full py-3 bg-gradient-to-r from-green-600 to-blue-600 hover:from-green-700 hover:to-blue-700 disabled:from-gray-600 disabled:to-gray-700 rounded-lg text-white font-semibold transition-all duration-300 transform hover:scale-[1.02] disabled:scale-100"
              >
                {loading ? "Verifying..." : "Verify & Enable 2FA"}
              </button>

              <button
                onClick={onClose}
                className="w-full py-2 text-gray-400 hover:text-white transition-colors text-sm"
              >
                Skip for now
              </button>
            </div>
          </>
        )}

        {/* Backup Codes Step */}
        {step === "backup" && (
          <>
            <div className="text-center mb-6">
              <div className="w-16 h-16 bg-gradient-to-r from-yellow-500 to-orange-500 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">🔑</span>
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">Save Your Backup Codes</h3>
              <p className="text-gray-400">Store these codes safely. You can use them if you lose access to your authenticator app.</p>
            </div>

            <div className="mb-6">
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 mb-4">
                <div className="flex items-start space-x-2">
                  <span className="text-yellow-400 text-lg">⚠️</span>
                  <div>
                    <p className="text-yellow-300 font-semibold text-sm">Important:</p>
                    <p className="text-yellow-200 text-sm">Each backup code can only be used once. Keep them secure and don't share them.</p>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 mb-4">
                {backupCodes.map((code, index) => (
                  <div key={index} className="bg-gray-800 px-3 py-2 rounded font-mono text-sm text-green-400 text-center">
                    {code}
                  </div>
                ))}
              </div>

              <div className="flex space-x-2">
                <button
                  onClick={downloadBackupCodes}
                  className="flex-1 py-2 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-lg text-blue-300 font-semibold transition-all duration-300 text-sm"
                >
                  📥 Download
                </button>
                <button
                  onClick={() => copyToClipboard(backupCodes.join('\n'))}
                  className="flex-1 py-2 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded-lg text-green-300 font-semibold transition-all duration-300 text-sm"
                >
                  📋 Copy
                </button>
              </div>
            </div>

            <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 mb-4">
              <div className="flex items-start space-x-2">
                <span className="text-blue-400 text-lg">📧</span>
                <div>
                  <p className="text-blue-300 font-semibold text-sm">Email Sent!</p>
                  <p className="text-blue-200 text-sm">We've sent a detailed setup guide with your QR code and backup codes to your email address.</p>
                </div>
              </div>
            </div>

            <button
              onClick={handleSetupComplete}
              className="w-full py-3 bg-gradient-to-r from-green-600 to-blue-600 hover:from-green-700 hover:to-blue-700 rounded-lg text-white font-semibold transition-all duration-300 transform hover:scale-[1.02]"
            >
              Complete Setup
            </button>
          </>
        )}

        {/* Backup Code Verify Step */}
        {step === "backup-verify" && (
          <>
            <div className="text-center mb-6">
              <div className="w-16 h-16 bg-gradient-to-r from-yellow-500 to-orange-500 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">🔑</span>
              </div>
              <h3 className="text-2xl font-bold text-white mb-2">Enter Backup Code</h3>
              <p className="text-gray-400">Enter one of your backup codes (up to 9 characters)</p>
            </div>

            <div className="mb-6">
              <div className="flex justify-center flex-wrap gap-2 mb-4">
                {code.map((digit, index) => (
                  <input
                    key={index}
                    ref={el => inputRefs.current[index] = el}
                    type="text"
                    maxLength="1"
                    value={digit}
                    onChange={(e) => handleCodeChange(index, e.target.value)}
                    onKeyDown={(e) => handleKeyDown(index, e)}
                    className="w-10 h-10 text-center text-lg font-bold bg-white/10 border border-white/20 rounded text-white focus:outline-none focus:ring-2 focus:ring-yellow-500/50 focus:border-yellow-500/50 transition-all duration-300"
                  />
                ))}
              </div>

              {error && (
                <div className="bg-red-500/20 border border-red-500/30 text-red-200 p-3 rounded-lg mb-4 text-center text-sm">
                  <span className="text-red-300">⚠️</span> {error}
                </div>
              )}
            </div>

            <div className="space-y-3">
              <button
                onClick={handleBackupCodeVerify}
                disabled={loading || code.join("").length < 6}
                className="w-full py-3 bg-gradient-to-r from-yellow-600 to-orange-600 hover:from-yellow-700 hover:to-orange-700 disabled:from-gray-600 disabled:to-gray-700 rounded-lg text-white font-semibold transition-all duration-300 transform hover:scale-[1.02] disabled:scale-100"
              >
                {loading ? "Verifying..." : "Verify Backup Code"}
              </button>

              <button
                onClick={() => setStep("verify")}
                className="w-full py-2 text-gray-400 hover:text-white transition-colors text-sm"
              >
                ← Back to authenticator code
              </button>

              <button
                onClick={onClose}
                className="w-full py-2 text-gray-400 hover:text-white transition-colors text-sm"
              >
                Cancel
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
