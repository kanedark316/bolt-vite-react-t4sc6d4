import React from 'react';
import { Play } from 'lucide-react';

const TVShowsPage = () => {
  const tvShows = [
    { id: 1, title: "Stranger Things", genre: "Sci-Fi", rating: 8.7 },
    { id: 2, title: "Breaking Bad", genre: "Drama", rating: 9.5 },
    { id: 3, title: "The Crown", genre: "Historical Drama", rating: 8.6 },
    { id: 4, title: "Game of Thrones", genre: "Fantasy", rating: 9.3 },
    { id: 5, title: "The Mandalorian", genre: "Sci-Fi", rating: 8.8 },
    { id: 6, title: "Friends", genre: "Comedy", rating: 8.9 },
    { id: 7, title: "The Office", genre: "Comedy", rating: 8.9 },
    { id: 8, title: "Stargate SG-1", genre: "Sci-Fi", rating: 8.9 },
    { id: 9, title: "Stargate Atlantis", genre: "Sci-Fi", rating: 8.9 },
    { id: 10, title: "Sliders", genre: "Sci-Fi", rating: 8.9 },
    { id: 11, title: "The X Files", genre: "Sci-Fi", rating: 8.9 },
    { id: 12, title: "Prison Break", genre: "Action", rating: 8.9 },
    { id: 13, title: "The Wire", genre: "Crime", rating: 8.9 },
    { id: 14, title: "Gangs of London", genre: "Crime", rating: 8.9 },
    { id: 15, title: "The Witcher", genre: "Fantasy", rating: 8.9 }
  ];

  return (
    <div className="min-h-screen bg-gray-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <h1 className="text-4xl font-bold text-white mb-8">TV Shows</h1>
        <p className="text-gray-300 text-lg mb-12">
          Explore our collection of TV shows. Find your next binge-worthy series here!
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          {tvShows.map(show => (
            <div
              key={show.id}
              className="bg-gray-800 rounded-lg overflow-hidden shadow-lg transform hover:scale-105 transition-transform duration-200"
            >
              <div className="p-6">
                <h2 className="text-xl font-semibold text-white mb-2">{show.title}</h2>
                <p className="text-gray-400 mb-2">Genre: {show.genre}</p>
                <div className="flex items-center justify-between">
                  <span className="text-yellow-400">★ {show.rating}/10</span>
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

export default TVShowsPage;