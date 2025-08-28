import { useState, useEffect } from "react";

export default function PasswordStrengthMeter({ password, onValidation }) {
  const [strength, setStrength] = useState(null);
  const [isValidating, setIsValidating] = useState(false);

  useEffect(() => {
    if (!password) {
      setStrength(null);
      onValidation?.(null);
      return;
    }

    const validatePassword = async () => {
      setIsValidating(true);
      try {
        // Client-side validation for immediate feedback
        const clientValidation = validatePasswordClient(password);
        setStrength(clientValidation);
        onValidation?.(clientValidation);
      } catch (error) {
        console.error('Password validation error:', error);
      } finally {
        setIsValidating(false);
      }
    };

    const debounceTimer = setTimeout(validatePassword, 300);
    return () => clearTimeout(debounceTimer);
  }, [password, onValidation]);

  const validatePasswordClient = (pwd) => {
    const errors = [];
    const warnings = [];
    let score = 0;

    // Check minimum length
    if (pwd.length < 8) {
      errors.push("Password must be at least 8 characters long");
    } else if (pwd.length >= 12) {
      score += 2;
    } else {
      score += 1;
      warnings.push("Consider using at least 12 characters for better security");
    }

    // Check for uppercase letters
    if (!/[A-Z]/.test(pwd)) {
      errors.push("Password must contain at least one uppercase letter");
    } else {
      score += 1;
    }

    // Check for lowercase letters
    if (!/[a-z]/.test(pwd)) {
      errors.push("Password must contain at least one lowercase letter");
    } else {
      score += 1;
    }

    // Check for numbers
    if (!/\d/.test(pwd)) {
      errors.push("Password must contain at least one number");
    } else {
      score += 1;
    }

    // Check for special characters
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd)) {
      errors.push("Password must contain at least one special character");
    } else {
      score += 1;
    }

    // Check for common patterns
    const commonPatterns = [
      /123456/,
      /password/i,
      /qwerty/i,
      /abc123/i,
      /admin/i,
      /letmein/i,
      /welcome/i
    ];

    for (const pattern of commonPatterns) {
      if (pattern.test(pwd)) {
        warnings.push("Avoid using common words or patterns");
        score -= 1;
        break;
      }
    }

    // Bonus points for length
    if (pwd.length >= 16) score += 1;
    if (pwd.length >= 20) score += 1;

    // Determine strength level
    let strengthLevel = 'very-weak';
    let strengthScore = Math.max(0, Math.min(10, score));

    if (strengthScore >= 8) {
      strengthLevel = 'very-strong';
    } else if (strengthScore >= 6) {
      strengthLevel = 'strong';
    } else if (strengthScore >= 4) {
      strengthLevel = 'medium';
    } else if (strengthScore >= 2) {
      strengthLevel = 'weak';
    }

    const isValidMasterPassword = errors.length === 0 && strengthScore >= 6;

    return {
      isValid: errors.length === 0,
      isValidMasterPassword,
      strength: strengthLevel,
      score: strengthScore,
      maxScore: 10,
      errors,
      warnings
    };
  };

  const getStrengthColor = (strengthLevel) => {
    const colors = {
      'very-weak': 'bg-red-500',
      'weak': 'bg-orange-500',
      'medium': 'bg-yellow-500',
      'strong': 'bg-green-500',
      'very-strong': 'bg-emerald-500'
    };
    return colors[strengthLevel] || 'bg-gray-500';
  };

  const getStrengthText = (strengthLevel) => {
    const texts = {
      'very-weak': 'Very Weak',
      'weak': 'Weak',
      'medium': 'Medium',
      'strong': 'Strong',
      'very-strong': 'Very Strong'
    };
    return texts[strengthLevel] || 'Unknown';
  };

  if (!password) return null;

  return (
    <div className="mt-3 space-y-3">
      {/* Strength Bar */}
      <div className="space-y-2">
        <div className="flex justify-between items-center">
          <span className="text-sm text-gray-300">Password Strength</span>
          {strength && (
            <span className={`text-sm font-medium ${
              strength.strength === 'very-weak' ? 'text-red-400' :
              strength.strength === 'weak' ? 'text-orange-400' :
              strength.strength === 'medium' ? 'text-yellow-400' :
              strength.strength === 'strong' ? 'text-green-400' :
              'text-emerald-400'
            }`}>
              {getStrengthText(strength.strength)}
            </span>
          )}
        </div>
        
        <div className="w-full bg-gray-700 rounded-full h-2">
          <div 
            className={`h-2 rounded-full transition-all duration-300 ${
              strength ? getStrengthColor(strength.strength) : 'bg-gray-500'
            }`}
            style={{ 
              width: strength ? `${(strength.score / strength.maxScore) * 100}%` : '0%' 
            }}
          ></div>
        </div>
      </div>

      {/* Requirements Checklist */}
      {strength && (
        <div className="space-y-2">
          <div className="text-sm text-gray-300">Requirements:</div>
          <div className="grid grid-cols-1 gap-1 text-xs">
            <div className={`flex items-center ${password.length >= 8 ? 'text-green-400' : 'text-red-400'}`}>
              <span className="mr-2">{password.length >= 8 ? '✓' : '✗'}</span>
              At least 8 characters
            </div>
            <div className={`flex items-center ${/[A-Z]/.test(password) ? 'text-green-400' : 'text-red-400'}`}>
              <span className="mr-2">{/[A-Z]/.test(password) ? '✓' : '✗'}</span>
              Uppercase letter
            </div>
            <div className={`flex items-center ${/[a-z]/.test(password) ? 'text-green-400' : 'text-red-400'}`}>
              <span className="mr-2">{/[a-z]/.test(password) ? '✓' : '✗'}</span>
              Lowercase letter
            </div>
            <div className={`flex items-center ${/\d/.test(password) ? 'text-green-400' : 'text-red-400'}`}>
              <span className="mr-2">{/\d/.test(password) ? '✓' : '✗'}</span>
              Number
            </div>
            <div className={`flex items-center ${/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password) ? 'text-green-400' : 'text-red-400'}`}>
              <span className="mr-2">{/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password) ? '✓' : '✗'}</span>
              Special character
            </div>
          </div>
        </div>
      )}

      {/* Errors */}
      {strength && strength.errors.length > 0 && (
        <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-3">
          <div className="text-red-300 text-sm font-medium mb-1">Issues:</div>
          <ul className="text-red-200 text-xs space-y-1">
            {strength.errors.map((error, index) => (
              <li key={index}>• {error}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Warnings */}
      {strength && strength.warnings.length > 0 && (
        <div className="bg-yellow-500/20 border border-yellow-500/30 rounded-lg p-3">
          <div className="text-yellow-300 text-sm font-medium mb-1">Suggestions:</div>
          <ul className="text-yellow-200 text-xs space-y-1">
            {strength.warnings.map((warning, index) => (
              <li key={index}>• {warning}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Master Password Validation */}
      {strength && !strength.isValidMasterPassword && (
        <div className="bg-orange-500/20 border border-orange-500/30 rounded-lg p-3">
          <div className="text-orange-300 text-sm font-medium flex items-center">
            <span className="mr-2">⚠️</span>
            Master Password Requirements
          </div>
          <div className="text-orange-200 text-xs mt-1">
            Your master password must be "Strong" or "Very Strong" to protect your vault.
          </div>
        </div>
      )}
    </div>
  );
}
