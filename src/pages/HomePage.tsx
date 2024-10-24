import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Tv2, Film, Trophy, LogIn, UserPlus } from 'lucide-react';

const HomePage = () => {
  const navigate = useNavigate();
  const isAuthenticated = localStorage.getItem('token') !== null;

  const handleProtectedNavigation = (path: string) => {
    if (isAuthenticated) {
      navigate(path);
    } else {
      navigate('/login', { state: { from: path } });
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 text-white">
      {/* Hero Section */}
      <div 
        className="relative h-[60vh] flex items-center justify-center"
        style={{
          backgroundImage: 'url("https://images.unsplash.com/photo-1574375927938-d5a98e8ffe85?auto=format&fit=crop&q=80")',
          backgroundSize: 'cover',
          backgroundPosition: 'center'
        }}
      >
        <div className="absolute inset-0 bg-black bg-opacity-60"></div>
        <div className="relative z-10 text-center px-4">
          <h1 className="text-5xl md:text-7xl font-bold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-purple-400 to-pink-600">
            Welcome to RewindTV
          </h1>
          <p className="text-xl md:text-2xl text-gray-200 max-w-2xl mx-auto">
            Your gateway to endless entertainment
          </p>
        </div>
      </div>

      {/* Cards Section */}
      <div className="max-w-7xl mx-auto px-4 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {!isAuthenticated && (
            <>
              <Link to="/login" className="transform hover:scale-105 transition-transform duration-300">
                <div className="bg-gray-800 rounded-xl p-6 hover:bg-gray-700 border border-gray-700 shadow-xl">
                  <div className="flex items-center justify-between mb-4">
                    <h2 className="text-2xl font-bold">Login</h2>
                    <LogIn className="w-8 h-8 text-purple-400" />
                  </div>
                  <p className="text-gray-400">Access your personalized experience</p>
                </div>
              </Link>

              <Link to="/register" className="transform hover:scale-105 transition-transform duration-300">
                <div className="bg-gray-800 rounded-xl p-6 hover:bg-gray-700 border border-gray-700 shadow-xl">
                  <div className="flex items-center justify-between mb-4">
                    <h2 className="text-2xl font-bold">Register</h2>
                    <UserPlus className="w-8 h-8 text-pink-400" />
                  </div>
                  <p className="text-gray-400">Join our streaming community</p>
                </div>
              </Link>
            </>
          )}

          <button 
            onClick={() => handleProtectedNavigation('/tv-shows')}
            className="transform hover:scale-105 transition-transform duration-300"
          >
            <div className="bg-gray-800 rounded-xl p-6 hover:bg-gray-700 border border-gray-700 shadow-xl">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-2xl font-bold">TV Shows</h2>
                <Tv2 className="w-8 h-8 text-blue-400" />
              </div>
              <p className="text-gray-400">Discover binge-worthy series</p>
            </div>
          </button>

          <button 
            onClick={() => handleProtectedNavigation('/movies')}
            className="transform hover:scale-105 transition-transform duration-300"
          >
            <div className="bg-gray-800 rounded-xl p-6 hover:bg-gray-700 border border-gray-700 shadow-xl">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-2xl font-bold">Movies</h2>
                <Film className="w-8 h-8 text-green-400" />
              </div>
              <p className="text-gray-400">Watch blockbuster hits</p>
            </div>
          </button>

          <button 
            onClick={() => handleProtectedNavigation('/ppv')}
            className="transform hover:scale-105 transition-transform duration-300"
          >
            <div className="bg-gray-800 rounded-xl p-6 hover:bg-gray-700 border border-gray-700 shadow-xl">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-2xl font-bold">PPV Events</h2>
                <Trophy className="w-8 h-8 text-yellow-400" />
              </div>
              <p className="text-gray-400">Experience premium live events</p>
            </div>
          </button>
        </div>
      </div>
    </div>
  );
};

export default HomePage;