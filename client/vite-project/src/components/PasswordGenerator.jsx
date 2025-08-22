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
        className="px-3 py-2 bg-purple-600 hover:bg-purple-700 rounded text-white text-sm"
      >
        🎲 Generate
      </button>

      {showGenerator && (
        <div className="absolute top-full left-0 mt-2 bg-gray-700 border border-gray-600 rounded-lg p-4 shadow-lg z-10 w-80">
          <h3 className="text-lg font-semibold mb-3">Password Generator</h3>
          
          <div className="space-y-3">
            <div>
              <label className="block text-sm mb-1">Length: {options.length}</label>
              <input
                type="range"
                min="4"
                max="50"
                value={options.length}
                onChange={(e) => setOptions({ ...options, length: parseInt(e.target.value) })}
                className="w-full"
              />
            </div>

            <div className="space-y-2">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={options.includeUppercase}
                  onChange={(e) => setOptions({ ...options, includeUppercase: e.target.checked })}
                  className="mr-2"
                />
                Uppercase (A-Z)
              </label>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={options.includeLowercase}
                  onChange={(e) => setOptions({ ...options, includeLowercase: e.target.checked })}
                  className="mr-2"
                />
                Lowercase (a-z)
              </label>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={options.includeNumbers}
                  onChange={(e) => setOptions({ ...options, includeNumbers: e.target.checked })}
                  className="mr-2"
                />
                Numbers (0-9)
              </label>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={options.includeSymbols}
                  onChange={(e) => setOptions({ ...options, includeSymbols: e.target.checked })}
                  className="mr-2"
                />
                Symbols (!@#$...)
              </label>
            </div>

            <button
              onClick={generatePassword}
              className="w-full py-2 bg-blue-600 hover:bg-blue-700 rounded text-white font-semibold"
            >
              Generate Password
            </button>

            {generatedPassword && (
              <div className="space-y-2">
                <div className="p-2 bg-gray-800 rounded font-mono text-sm break-all">
                  {generatedPassword}
                </div>
                
                <div className="flex items-center justify-between">
                  <span className={`text-${strength.color}-400 text-sm`}>
                    Strength: {strength.text}
                  </span>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => navigator.clipboard.writeText(generatedPassword)}
                      className="px-2 py-1 bg-gray-600 hover:bg-gray-500 rounded text-xs"
                    >
                      Copy
                    </button>
                    <button
                      onClick={usePassword}
                      className="px-2 py-1 bg-green-600 hover:bg-green-700 rounded text-xs"
                    >
                      Use This
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>

          <button
            onClick={() => setShowGenerator(false)}
            className="absolute top-2 right-2 text-gray-400 hover:text-white"
          >
            ✕
          </button>
        </div>
      )}
    </div>
  );
}
