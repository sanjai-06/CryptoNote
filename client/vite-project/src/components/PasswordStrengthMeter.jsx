import { useState, useEffect } from "react";

const getStrengthColor = (score) => {
  if (score <= 2) return "#ef4444"; // red-500
  if (score <= 4) return "#f59e0b"; // amber-500
  if (score <= 6) return "#3b82f6"; // blue-500
  return "#10b981"; // emerald-500
};

const getStrengthText = (score) => {
  if (score <= 2) return "Weak";
  if (score <= 4) return "Fair";
  if (score <= 6) return "Good";
  return "Strong";
};

export default function PasswordStrengthMeter({ password, onValidation, isMasterPassword = false }) {
  const [strength, setStrength] = useState({
    score: 0,
    feedback: {
      suggestions: [],
      warning: "",
    },
    errors: [],
    warnings: [],
    isValid: false,
    isValidMasterPassword: false,
  });
  
  const [isValidating, setIsValidating] = useState(false);

  useEffect(() => {
    if (!password) {
      setStrength(prev => ({
        ...prev,
        score: 0,
        feedback: { suggestions: [], warning: "" },
        errors: [],
        warnings: [],
        isValid: false,
        isValidMasterPassword: false,
      }));
      onValidation?.(null);
      return;
    }

    const validatePassword = () => {
      setIsValidating(true);
      try {
        const result = checkPasswordStrength(password);
        setStrength(result);
        onValidation?.(result);
      } catch (error) {
        console.error('Password validation error:', error);
      } finally {
        setIsValidating(false);
      }
    };

    const debounceTimer = setTimeout(validatePassword, 300);
    return () => clearTimeout(debounceTimer);
  }, [password, onValidation, isMasterPassword]);

  const checkPasswordStrength = (pwd) => {
    let score = 0;
    const suggestions = [];
    const errors = [];
    const warnings = [];
    let warning = "";

    // Length check
    if (pwd.length < 8) {
      errors.push("Password must be at least 8 characters long");
    } else if (pwd.length < 12) {
      score += 1;
      suggestions.push("Consider using at least 12 characters");
    } else {
      score += 2;
    }

    // Character variety
    const hasLower = /[a-z]/.test(pwd);
    const hasUpper = /[A-Z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSpecial = /[^A-Za-z0-9]/.test(pwd);

    if (!hasLower) errors.push("Must contain at least one lowercase letter");
    if (!hasUpper) errors.push("Must contain at least one uppercase letter");
    if (!hasNumber) errors.push("Must contain at least one number");
    if (!hasSpecial) errors.push("Must contain at least one special character");

    if (hasLower && hasUpper) score += 1;
    if (hasNumber) score += 1;
    if (hasSpecial) score += 2;

    // Common patterns check
    const commonPatterns = [
      '123456', 'password', 'qwerty', '111111',
      'admin', 'welcome', 'letmein', 'monkey', 'sunshine'
    ];
    
    if (commonPatterns.some(pattern => pwd.toLowerCase().includes(pattern))) {
      score = Math.max(1, score - 2);
      warnings.push("Avoid using common words or patterns");
      if (!warning) warning = "Avoid common words and patterns";
    }

    // Sequential characters check
    if (/([a-zA-Z0-9])\1{2,}/.test(pwd)) {
      score = Math.max(1, score - 1);
      warnings.push("Avoid repeated characters");
      if (!warning) warning = "Avoid repeated characters";
    }

    // Add suggestions
    if (!hasLower) suggestions.push("Add lowercase letters");
    if (!hasUpper) suggestions.push("Add uppercase letters");
    if (!hasNumber) suggestions.push("Add numbers");
    if (!hasSpecial) suggestions.push("Add special characters (!@#$%^&*)");

    // Bonus points for length
    if (pwd.length >= 16) score += 1;
    if (pwd.length >= 20) score += 1;

    // Limit score to 0-10 range
    score = Math.max(0, Math.min(10, score));

    // Determine if valid
    const isValid = errors.length === 0;
    const isValidMasterPassword = isValid && score >= 6; // At least "Good" strength

    return {
      score,
      feedback: {
        suggestions: suggestions.slice(0, 3), // Limit to top 3 suggestions
        warning,
      },
      errors: [...new Set(errors)], // Remove duplicates
      warnings: [...new Set(warnings)], // Remove duplicates
      isValid,
      isValidMasterPassword,
    };
  };

  if (!password) return null;

  const strengthPercentage = Math.min(100, (strength.score / 10) * 100);
  const strengthColor = getStrengthColor(strength.score);
  const strengthText = getStrengthText(strength.score);

  const requirements = [
    { label: '8+ characters', test: password.length >= 8 },
    { label: 'Uppercase letter', test: /[A-Z]/.test(password) },
    { label: 'Lowercase letter', test: /[a-z]/.test(password) },
    { label: 'Number', test: /[0-9]/.test(password) },
    { label: 'Special character', test: /[^A-Za-z0-9]/.test(password) },
    { label: '12+ characters (recommended)', test: password.length >= 12 },
  ];

  return (
    <div className="mt-3 space-y-3">
      <div className="space-y-2">
        {isValidating ? (
          <div className="text-sm text-gray-500">Checking password strength...</div>
        ) : (
          <div className="space-y-3">
            <div>
              <div className="flex items-center justify-between text-sm mb-1">
                <span className="font-medium">Password Strength:</span>
                <span className="font-semibold" style={{ color: strengthColor }}>
                  {strengthText}
                </span>
              </div>
              
              <div className="w-full bg-gray-200 rounded-full h-2 overflow-hidden">
                <div 
                  className="h-full rounded-full transition-all duration-500 ease-out"
                  style={{
                    width: `${strengthPercentage}%`,
                    backgroundColor: strengthColor,
                    boxShadow: `0 0 8px ${strengthColor}80`,
                  }}
                />
              </div>
            </div>
            
            {strength.feedback.warning && (
              <div className="mt-2 p-2 bg-amber-50 border border-amber-200 rounded-md text-amber-700 text-sm">
                <div className="flex items-start">
                  <svg className="h-5 w-5 text-amber-500 mr-2 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  <span>{strength.feedback.warning}</span>
                </div>
              </div>
            )}
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
              {requirements.map((req, i) => (
                <div key={i} className="flex items-center">
                  <span className={`inline-flex items-center justify-center w-5 h-5 mr-2 rounded-full ${req.test ? 'bg-emerald-100 text-emerald-600' : 'bg-gray-100 text-gray-400'}`}>
                    {req.test ? (
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    ) : (
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    )}
                  </span>
                  <span className={req.test ? 'text-gray-600' : 'text-gray-400'}>{req.label}</span>
                </div>
              ))}
            </div>
            
            {strength.feedback.suggestions.length > 0 && (
              <div className="mt-2 space-y-1">
                <p className="text-xs font-medium text-gray-500">SUGGESTIONS:</p>
                <ul className="text-sm text-gray-600 space-y-1">
                  {strength.feedback.suggestions.map((suggestion, i) => (
                    <li key={i} className="flex items-start">
                      <svg className="h-4 w-4 text-emerald-500 mr-1.5 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      {suggestion}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* Error Messages */}
        {strength.errors.length > 0 && (
          <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded-md">
            <h4 className="text-sm font-medium text-red-700 mb-2">Password must contain:</h4>
            <ul className="text-sm text-red-600 space-y-1">
              {strength.errors.map((error, i) => (
                <li key={i} className="flex items-start">
                  <svg className="h-4 w-4 text-red-500 mr-1.5 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                  {error}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Master Password Warning */}
        {isMasterPassword && !strength.isValidMasterPassword && (
          <div className="mt-3 p-3 bg-amber-50 border border-amber-200 rounded-md">
            <div className="flex items-start">
              <svg className="h-5 w-5 text-amber-500 mr-2 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              <div>
                <h4 className="text-sm font-medium text-amber-700">Master Password Requirements</h4>
                <p className="text-sm text-amber-600 mt-1">
                  For security, your master password must be "Good" or "Strong" to protect your vault.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
