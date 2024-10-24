import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { Play, Search } from 'lucide-react';

const MoviesPage = () => {
  const location = useLocation();
  const [searchQuery, setSearchQuery] = useState('');
  const [movies] = useState([
    { id: 1, title: "Inception", genre: "Sci-Fi", rating: 8.8, year: 2010 },
    { id: 2, title: "The Dark Knight", genre: "Action", rating: 9.0, year: 2008 },
    { id: 3, title: "Interstellar", genre: "Sci-Fi", rating: 8.6, year: 2014 },
    { id: 4, title: "Pulp Fiction", genre: "Crime", rating: 8.9, year: 1994 },
    { id: 5, title: "The Matrix", genre: "Sci-Fi", rating: 8.7, year: 1999 },
    { id: 6, title: "Forrest Gump", genre: "Drama", rating: 8.8, year: 1994 },
    { id: 7, title: "The Shawshank Redemption", genre: "Drama", rating: 9.3, year: 1994 },
    { id: 8, title: "The Godfather", genre: "Crime", rating: 9.2, year: 1972 }
  ]);

  useEffect(() => {
    const query = new URLSearchParams(location.search).get('search');
    if (query) {
      setSearchQuery(query);
    }
  }, [location.search]);

  const filteredMovies = searchQuery
    ? movies.filter(movie => 
        movie.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        movie.genre.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : movies;

  return (
    <div className="min-h-screen bg-gray-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="flex flex-col md:flex-row justify-between items-center mb-12">
          <h1 className="text-4xl font-bold text-white mb-4 md:mb-0">Movies</h1>
          <div className="relative">
            <input
              type="text"
              placeholder="Search movies..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full md:w-64 px-4 py-2 pl-10 bg-gray-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            <Search className="absolute left-3 top-2.5 text-gray-400" size={20} />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          {filteredMovies.map(movie => (
            <div
              key={movie.id}
              className="bg-gray-800 rounded-lg overflow-hidden shadow-lg transform hover:scale-105 transition-transform duration-200"
            >
              <div className="p-6">
                <h2 className="text-xl font-semibold text-white mb-2">{movie.title}</h2>
                <p className="text-gray-400 mb-2">
                  {movie.genre} • {movie.year}
                </p>
                <div className="flex items-center justify-between">
                  <span className="text-yellow-400">★ {movie.rating}/10</span>
                  <button className="flex items-center space-x-1 bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-1 rounded-md">
                    <Play size={16} />
                    <span>Watch</span>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default MoviesPage;