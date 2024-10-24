import React, { useState, useEffect } from 'react';
import AdminLayout from '../components/AdminLayout';
import { BarChart3, TrendingUp, Heart, Star } from 'lucide-react';
import { getAnalytics } from '../../api/admin';

const AdminDashboardPage = () => {
  const [analytics, setAnalytics] = useState({
    mostViewed: [],
    favorites: [],
    highestRated: [],
    recentActivity: []
  });

  useEffect(() => {
    const fetchAnalytics = async () => {
      try {
        const data = await getAnalytics();
        setAnalytics(data);
      } catch (error) {
        console.error('Failed to fetch analytics:', error);
      }
    };

    fetchAnalytics();
  }, []);

  return (
    <AdminLayout>
      <div className="p-6">
        <h1 className="text-2xl font-bold text-white mb-6">Dashboard</h1>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Most Viewed Content */}
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center mb-4">
              <BarChart3 className="text-indigo-500 mr-2" />
              <h2 className="text-xl font-semibold text-white">Most Viewed</h2>
            </div>
            <div className="space-y-4">
              {analytics.mostViewed.map((item: any) => (
                <div key={item.id} className="flex justify-between items-center">
                  <span className="text-gray-300">{item.title}</span>
                  <span className="text-gray-400">{item.views} views</span>
                </div>
              ))}
            </div>
          </div>

          {/* Trending Content */}
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center mb-4">
              <TrendingUp className="text-green-500 mr-2" />
              <h2 className="text-xl font-semibold text-white">Trending</h2>
            </div>
            <div className="space-y-4">
              {analytics.recentActivity.map((item: any) => (
                <div key={item.id} className="flex justify-between items-center">
                  <span className="text-gray-300">{item.title}</span>
                  <span className="text-gray-400">{item.trend}%</span>
                </div>
              ))}
            </div>
          </div>

          {/* Most Favorited */}
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center mb-4">
              <Heart className="text-red-500 mr-2" />
              <h2 className="text-xl font-semibold text-white">Most Favorited</h2>
            </div>
            <div className="space-y-4">
              {analytics.favorites.map((item: any) => (
                <div key={item.id} className="flex justify-between items-center">
                  <span className="text-gray-300">{item.title}</span>
                  <span className="text-gray-400">{item.favorites} favorites</span>
                </div>
              ))}
            </div>
          </div>

          {/* Highest Rated */}
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center mb-4">
              <Star className="text-yellow-500 mr-2" />
              <h2 className="text-xl font-semibold text-white">Highest Rated</h2>
            </div>
            <div className="space-y-4">
              {analytics.highestRated.map((item: any) => (
                <div key={item.id} className="flex justify-between items-center">
                  <span className="text-gray-300">{item.title}</span>
                  <span className="text-gray-400">★ {item.rating}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default AdminDashboardPage;