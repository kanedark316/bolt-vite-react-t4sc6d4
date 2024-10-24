import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Calendar, Clock, DollarSign, Ticket } from 'lucide-react';

interface Event {
  id: string;
  name: string;
  dates: {
    start: {
      dateTime: string;
    };
  };
  classifications: Array<{
    genre?: {
      name: string;
    };
  }>;
  priceRanges?: Array<{
    min: number;
    max: number;
  }>;
}

const LivePage = () => {
  const [events, setEvents] = useState<Event[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<string | null>(null);
  const [filter, setFilter] = useState('All');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchEvents();
  }, []);

  const fetchEvents = async () => {
    const apiKey = 'bYYNlQhfDJAo7MIqqllsfh3Mu6vjvEgM';
    const startDateTime = '2024-01-01T00:00:00Z';
    const endDateTime = '2025-12-31T23:59:59Z';

    try {
      const response = await axios.get('https://app.ticketmaster.com/discovery/v2/events.json', {
        params: {
          apikey: apiKey,
          classificationName: 'music',
          startDateTime,
          endDateTime,
          size: 200,
        }
      });

      if (response.data._embedded?.events) {
        setEvents(response.data._embedded.events);
      } else {
        setError('No events found');
      }
    } catch (err) {
      setError('Failed to fetch events');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const genres = ['All', ...new Set(events.map(event => 
    event.classifications[0]?.genre?.name || 'Uncategorized'
  ))];

  const filteredEvents = filter === 'All' 
    ? events 
    : events.filter(event => event.classifications[0]?.genre?.name === filter);

  const handlePurchase = (eventId: string) => {
    setSelectedEvent(eventId);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-red-500 text-xl">{error}</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <h1 className="text-4xl font-bold text-white mb-8">Live Concert Events</h1>
        
        {selectedEvent ? (
          <div className="bg-gray-800 rounded-lg p-8">
            <h2 className="text-2xl font-bold text-white mb-4">Live Stream</h2>
            <div className="aspect-w-16 aspect-h-9 bg-gray-700 rounded-lg flex items-center justify-center">
              <p className="text-gray-400">Live stream of the concert would appear here.</p>
            </div>
          </div>
        ) : (
          <>
            <div className="mb-8">
              <label htmlFor="genre-filter" className="text-gray-300 mr-3">
                Filter by genre:
              </label>
              <select 
                id="genre-filter" 
                value={filter} 
                onChange={(e) => setFilter(e.target.value)}
                className="bg-gray-800 text-white rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              >
                {genres.map(genre => (
                  <option key={genre} value={genre}>{genre}</option>
                ))}
              </select>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
              {filteredEvents.map(event => (
                <div 
                  key={event.id}
                  className="bg-gray-800 rounded-lg overflow-hidden shadow-lg transform hover:scale-105 transition-transform duration-200"
                >
                  <div className="p-6">
                    <h3 className="text-xl font-semibold text-white mb-4">{event.name}</h3>
                    
                    <div className="space-y-3 text-gray-400">
                      <div className="flex items-center">
                        <Calendar size={16} className="mr-2" />
                        <span>
                          {new Date(event.dates.start.dateTime).toLocaleDateString()}
                        </span>
                      </div>
                      
                      <div className="flex items-center">
                        <Clock size={16} className="mr-2" />
                        <span>
                          {new Date(event.dates.start.dateTime).toLocaleTimeString()}
                        </span>
                      </div>

                      {event.priceRanges && (
                        <div className="flex items-center">
                          <DollarSign size={16} className="mr-2" />
                          <span>
                            ${event.priceRanges[0].min} - ${event.priceRanges[0].max}
                          </span>
                        </div>
                      )}
                    </div>

                    <button 
                      onClick={() => handlePurchase(event.id)}
                      className="mt-6 w-full flex items-center justify-center space-x-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md transition-colors duration-200"
                    >
                      <Ticket size={16} />
                      <span>Purchase Tickets</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default LivePage;