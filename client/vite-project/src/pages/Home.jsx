import { Link } from "react-router-dom";

export default function Home() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-900 via-purple-900 to-pink-900 text-white relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse"></div>
        <div className="absolute top-3/4 right-1/4 w-96 h-96 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse animation-delay-2000"></div>
        <div className="absolute bottom-1/4 left-1/3 w-96 h-96 bg-pink-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-pulse animation-delay-4000"></div>
      </div>

      <div className="relative z-10 flex items-center justify-center min-h-screen">
        <div className="text-center max-w-6xl mx-auto px-6">
          {/* Hero Section */}
          <div className="mb-16">
            <div className="inline-flex items-center justify-center w-24 h-24 bg-gradient-to-r from-blue-500 to-purple-600 rounded-full mb-8 shadow-2xl">
              <span className="text-4xl">🔐</span>
            </div>

            <h1 className="text-7xl md:text-8xl font-extrabold mb-6 bg-gradient-to-r from-blue-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
              CryptoNote
            </h1>

            <p className="text-2xl md:text-3xl text-gray-300 mb-4 font-light">
              Your Digital Vault
            </p>

            <p className="text-lg text-gray-400 mb-12 max-w-3xl mx-auto leading-relaxed">
              Experience the future of password management with military-grade encryption,
              intuitive design, and seamless synchronization across all your devices.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 justify-center mb-16">
              <Link
                to="/register"
                className="group relative px-8 py-4 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 rounded-xl text-white font-bold text-lg transition-all duration-300 transform hover:scale-105 shadow-2xl hover:shadow-blue-500/25"
              >
                <span className="relative z-10">Start Your Journey</span>
                <div className="absolute inset-0 bg-gradient-to-r from-blue-400 to-purple-400 rounded-xl blur opacity-0 group-hover:opacity-20 transition-opacity duration-300"></div>
              </Link>
              <Link
                to="/login"
                className="px-8 py-4 bg-white/10 hover:bg-white/20 backdrop-blur-sm border border-white/20 rounded-xl text-white font-semibold text-lg transition-all duration-300 transform hover:scale-105"
              >
                Welcome Back
              </Link>
            </div>
          </div>

          {/* Features Grid */}
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8 mb-16">
            <div className="group p-8 bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl hover:bg-white/10 transition-all duration-300 transform hover:scale-105">
              <div className="w-16 h-16 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300">
                <span className="text-2xl">🛡️</span>
              </div>
              <h3 className="text-xl font-bold mb-4 text-blue-300">Military-Grade Security</h3>
              <p className="text-gray-400 leading-relaxed">
                AES-256-CBC encryption ensures your passwords are protected with the same security used by governments.
              </p>
            </div>

            <div className="group p-8 bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl hover:bg-white/10 transition-all duration-300 transform hover:scale-105">
              <div className="w-16 h-16 bg-gradient-to-r from-green-500 to-emerald-500 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300">
                <span className="text-2xl">⚡</span>
              </div>
              <h3 className="text-xl font-bold mb-4 text-green-300">Lightning Fast</h3>
              <p className="text-gray-400 leading-relaxed">
                Built with modern React and optimized APIs for instant access to your passwords anywhere, anytime.
              </p>
            </div>

            <div className="group p-8 bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl hover:bg-white/10 transition-all duration-300 transform hover:scale-105">
              <div className="w-16 h-16 bg-gradient-to-r from-purple-500 to-violet-500 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300">
                <span className="text-2xl">🎨</span>
              </div>
              <h3 className="text-xl font-bold mb-4 text-purple-300">Beautiful Design</h3>
              <p className="text-gray-400 leading-relaxed">
                Intuitive interface with smooth animations and modern design that makes security feel effortless.
              </p>
            </div>

            <div className="group p-8 bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl hover:bg-white/10 transition-all duration-300 transform hover:scale-105">
              <div className="w-16 h-16 bg-gradient-to-r from-yellow-500 to-orange-500 rounded-2xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300">
                <span className="text-2xl">🚀</span>
              </div>
              <h3 className="text-xl font-bold mb-4 text-yellow-300">Smart Features</h3>
              <p className="text-gray-400 leading-relaxed">
                Advanced password generator, strength analysis, and intelligent organization keep you secure.
              </p>
            </div>
          </div>

          {/* Stats Section */}
          <div className="grid grid-cols-3 gap-8 mb-16">
            <div className="text-center">
              <div className="text-4xl font-bold text-blue-400 mb-2">256-bit</div>
              <div className="text-gray-400">Encryption</div>
            </div>
            <div className="text-center">
              <div className="text-4xl font-bold text-purple-400 mb-2">100%</div>
              <div className="text-gray-400">Secure</div>
            </div>
            <div className="text-center">
              <div className="text-4xl font-bold text-pink-400 mb-2">∞</div>
              <div className="text-gray-400">Passwords</div>
            </div>
          </div>

          {/* Footer */}
          <div className="text-center text-gray-500">
            <p className="mb-2">Powered by the MERN Stack</p>
            <div className="flex justify-center space-x-6 text-sm">
              <span className="flex items-center"><span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>MongoDB</span>
              <span className="flex items-center"><span className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></span>Express.js</span>
              <span className="flex items-center"><span className="w-2 h-2 bg-blue-500 rounded-full mr-2"></span>React</span>
              <span className="flex items-center"><span className="w-2 h-2 bg-green-600 rounded-full mr-2"></span>Node.js</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
