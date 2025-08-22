import { Link } from "react-router-dom";

export default function Home() {
  return (
    <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
      <div className="text-center max-w-4xl mx-auto px-6">
        <h1 className="text-6xl font-bold mb-6 flex items-center justify-center">
          <span className="mr-4">🔒</span> CryptoNote
        </h1>
        
        <p className="text-xl text-gray-300 mb-8 leading-relaxed">
          A secure password manager with server-side encryption, built with the MERN stack.
          Keep your passwords safe and organized in one place.
        </p>

        <div className="grid md:grid-cols-2 gap-6 mb-12">
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-2xl font-semibold mb-3 text-blue-400">🛡️ Secure</h3>
            <p className="text-gray-300">
              Your passwords are encrypted using AES-256-CBC encryption before being stored in our database.
            </p>
          </div>
          
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-2xl font-semibold mb-3 text-green-400">⚡ Fast</h3>
            <p className="text-gray-300">
              Built with React and Express.js for lightning-fast performance and smooth user experience.
            </p>
          </div>
          
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-2xl font-semibold mb-3 text-purple-400">🎯 Simple</h3>
            <p className="text-gray-300">
              Clean, intuitive interface makes managing your passwords effortless and stress-free.
            </p>
          </div>
          
          <div className="bg-gray-800 p-6 rounded-lg">
            <h3 className="text-2xl font-semibold mb-3 text-yellow-400">🔄 Organized</h3>
            <p className="text-gray-300">
              Add, edit, delete, and organize all your passwords in one secure location.
            </p>
          </div>
        </div>

        <div className="space-x-4">
          <Link
            to="/register"
            className="inline-block px-8 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg text-white font-semibold text-lg transition-colors"
          >
            Get Started
          </Link>
          <Link
            to="/login"
            className="inline-block px-8 py-3 bg-gray-700 hover:bg-gray-600 rounded-lg text-white font-semibold text-lg transition-colors"
          >
            Login
          </Link>
        </div>

        <div className="mt-12 text-gray-400">
          <p>Built with MongoDB, Express.js, React, and Node.js</p>
        </div>
      </div>
    </div>
  );
}
