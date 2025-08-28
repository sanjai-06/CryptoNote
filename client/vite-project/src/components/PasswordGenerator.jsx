import { useState } from "react";

export default function PasswordGenerator({ onPasswordGenerated }) {
  const [options, setOptions] = useState({
    length: 12,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: true,
  });
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [showGenerator, setShowGenerator] = useState(false);

  const generatePassword = () => {
    let charset = "";
    if (options.includeLowercase) charset += "abcdefghijklmnopqrstuvwxyz";
    if (options.includeUppercase) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (options.includeNumbers) charset += "0123456789";
    if (options.includeSymbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    if (charset === "") {
      alert("Please select at least one character type");
      return;
    }

    let password = "";
    for (let i = 0; i < options.length; i++) {
      password += charset.charAt(Math.floor(Math.random() * charset.length));
    }

    setGeneratedPassword(password);
  };

  const getPasswordStrength = (password) => {
    if (!password) return { score: 0, text: "No password", color: "gray" };
    
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    if (score <= 2) return { score, text: "Weak", color: "red" };
    if (score <= 4) return { score, text: "Medium", color: "yellow" };
    return { score, text: "Strong", color: "green" };
  };

  const strength = getPasswordStrength(generatedPassword);

  const usePassword = () => {
    onPasswordGenerated(generatedPassword);
    setShowGenerator(false);
  };

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setShowGenerator(!showGenerator)}
        className="p-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/30 rounded-lg text-purple-300 transition-all duration-200 hover:scale-110"
        title="Generate secure password"
      >
        🎲
      </button>

      {showGenerator && (
        <div className="absolute top-full right-0 mt-2 bg-gray-900/95 backdrop-blur-lg border border-white/20 rounded-2xl p-6 shadow-2xl z-50 w-96">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white flex items-center">
              <span className="mr-2">🎲</span> Password Generator
            </h3>
            <button
              onClick={() => setShowGenerator(false)}
              className="p-1 text-gray-400 hover:text-white transition-colors"
            >
              ✕
            </button>
          </div>

          <div className="space-y-4">
            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="text-sm text-gray-300">Password Length</label>
                <span className="text-purple-400 font-semibold">{options.length}</span>
              </div>
              <input
                type="range"
                min="4"
                max="50"
                value={options.length}
                onChange={(e) => setOptions({ ...options, length: parseInt(e.target.value) })}
                className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer slider"
              />
            </div>

            <div className="space-y-3">
              <p className="text-sm text-gray-300 font-medium">Character Types:</p>
              <div className="grid grid-cols-2 gap-3">
                <label className="flex items-center p-3 bg-white/5 rounded-lg border border-white/10 hover:bg-white/10 transition-colors cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeUppercase}
                    onChange={(e) => setOptions({ ...options, includeUppercase: e.target.checked })}
                    className="mr-3 w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
                  />
                  <div>
                    <div className="text-sm font-medium text-white">ABC</div>
                    <div className="text-xs text-gray-400">Uppercase</div>
                  </div>
                </label>

                <label className="flex items-center p-3 bg-white/5 rounded-lg border border-white/10 hover:bg-white/10 transition-colors cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeLowercase}
                    onChange={(e) => setOptions({ ...options, includeLowercase: e.target.checked })}
                    className="mr-3 w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
                  />
                  <div>
                    <div className="text-sm font-medium text-white">abc</div>
                    <div className="text-xs text-gray-400">Lowercase</div>
                  </div>
                </label>

                <label className="flex items-center p-3 bg-white/5 rounded-lg border border-white/10 hover:bg-white/10 transition-colors cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeNumbers}
                    onChange={(e) => setOptions({ ...options, includeNumbers: e.target.checked })}
                    className="mr-3 w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
                  />
                  <div>
                    <div className="text-sm font-medium text-white">123</div>
                    <div className="text-xs text-gray-400">Numbers</div>
                  </div>
                </label>

                <label className="flex items-center p-3 bg-white/5 rounded-lg border border-white/10 hover:bg-white/10 transition-colors cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeSymbols}
                    onChange={(e) => setOptions({ ...options, includeSymbols: e.target.checked })}
                    className="mr-3 w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 rounded focus:ring-purple-500"
                  />
                  <div>
                    <div className="text-sm font-medium text-white">!@#</div>
                    <div className="text-xs text-gray-400">Symbols</div>
                  </div>
                </label>
              </div>
            </div>

            <button
              onClick={generatePassword}
              className="w-full py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 rounded-xl text-white font-semibold transition-all duration-300 transform hover:scale-[1.02]"
            >
              <span className="mr-2">🎲</span> Generate Password
            </button>

            {generatedPassword && (
              <div className="space-y-4">
                <div className="p-4 bg-gray-800/50 border border-white/10 rounded-xl">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-gray-300">Generated Password:</span>
                    <div className="flex items-center space-x-2">
                      <div className={`w-2 h-2 rounded-full ${
                        strength.color === 'red' ? 'bg-red-500' :
                        strength.color === 'yellow' ? 'bg-yellow-500' : 'bg-green-500'
                      }`}></div>
                      <span className={`text-sm font-medium ${
                        strength.color === 'red' ? 'text-red-400' :
                        strength.color === 'yellow' ? 'text-yellow-400' : 'text-green-400'
                      }`}>
                        {strength.text}
                      </span>
                    </div>
                  </div>
                  <div className="p-3 bg-gray-900/50 rounded-lg font-mono text-sm break-all text-white border border-white/10">
                    {generatedPassword}
                  </div>
                </div>

                <div className="flex space-x-3">
                  <button
                    onClick={() => navigator.clipboard.writeText(generatedPassword)}
                    className="flex-1 py-2 bg-gray-600/20 hover:bg-gray-600/30 border border-gray-600/30 rounded-lg text-gray-300 font-medium transition-all duration-200"
                  >
                    <span className="mr-2">📋</span> Copy
                  </button>
                  <button
                    onClick={usePassword}
                    className="flex-1 py-2 bg-green-600/20 hover:bg-green-600/30 border border-green-600/30 rounded-lg text-green-300 font-medium transition-all duration-200"
                  >
                    <span className="mr-2">✅</span> Use This
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
