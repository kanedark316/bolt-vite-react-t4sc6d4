import React, { useState } from 'react';
import AdminLayout from '../components/AdminLayout';
import { Upload, Save, Edit } from 'lucide-react';
import adminAPI from '../../api/admin';

const AddContentPage = () => {
  const [contentType, setContentType] = useState('movie');
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    genre: '',
    ageRating: '',
    contentWarnings: [],
    releaseYear: '',
    duration: '',
    seasons: '1',
    episodes: '1'
  });
  const [file, setFile] = useState<File | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [loading, setLoading] = useState(false);

  const contentWarningOptions = [
    'Violence',
    'Strong Language',
    'Sexual Content',
    'Drug Use',
    'Gore',
    'Disturbing Content'
  ];

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleWarningToggle = (warning: string) => {
    setFormData(prev => ({
      ...prev,
      contentWarnings: prev.contentWarnings.includes(warning)
        ? prev.contentWarnings.filter(w => w !== warning)
        : [...prev.contentWarnings, warning]
    }));
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      let s3Url = '';
      if (file) {
        // Upload to appropriate S3 bucket based on content type
        s3Url = await adminAPI.uploadToS3(file, contentType);
      }

      // Add content to database
      await adminAPI.addContent({
        ...formData,
        type: contentType,
        fileUrl: s3Url
      });

      // Reset form
      setFormData({
        title: '',
        description: '',
        genre: '',
        ageRating: '',
        contentWarnings: [],
        releaseYear: '',
        duration: '',
        seasons: '1',
        episodes: '1'
      });
      setFile(null);
      setIsEditing(false);
    } catch (error) {
      console.error('Failed to add content:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AdminLayout>
      <div className="p-6 max-w-4xl mx-auto">
        <h1 className="text-2xl font-bold text-white mb-6">Add New Content</h1>
        
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Content Type Selection */}
          <div className="bg-gray-800 p-6 rounded-lg">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Content Type
            </label>
            <div className="flex space-x-4">
              {['movie', 'tv-show', 'live-event'].map(type => (
                <button
                  key={type}
                  type="button"
                  onClick={() => setContentType(type)}
                  className={`px-4 py-2 rounded-md ${
                    contentType === type
                      ? 'bg-indigo-600 text-white'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {type.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
                </button>
              ))}
            </div>
          </div>

          {/* Basic Information */}
          <div className="bg-gray-800 p-6 rounded-lg space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Title
              </label>
              <input
                type="text"
                name="title"
                value={formData.title}
                onChange={handleInputChange}
                className="w-full rounded-md bg-gray-700 border-gray-600 text-white"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Description
              </label>
              <textarea
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                rows={4}
                className="w-full rounded-md bg-gray-700 border-gray-600 text-white"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Genre
                </label>
                <select
                  name="genre"
                  value={formData.genre}
                  onChange={handleInputChange}
                  className="w-full rounded-md bg-gray-700 border-gray-600 text-white"
                  required
                >
                  <option value="">Select Genre</option>
                  <option value="action">Action</option>
                  <option value="comedy">Comedy</option>
                  <option value="drama">Drama</option>
                  <option value="sci-fi">Sci-Fi</option>
                  <option value="horror">Horror</option>
                  <option value="documentary">Documentary</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Age Rating
                </label>
                <select
                  name="ageRating"
                  value={formData.ageRating}
                  onChange={handleInputChange}
                  className="w-full rounded-md bg-gray-700 border-gray-600 text-white"
                  required
                >
                  <option value="">Select Rating</option>
                  <option value="U">U</option>
                  <option value="PG">PG</option>
                  <option value="12">12</option>
                  <option value="15">15</option>
                  <option value="18">18</option>
                </select>
              </div>
            </div>
          </div>

          {/* Content Warnings */}
          <div className="bg-gray-800 p-6 rounded-lg">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Content Warnings
            </label>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              {contentWarningOptions.map(warning => (
                <label key={warning} className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={formData.contentWarnings.includes(warning)}
                    onChange={() => handleWarningToggle(warning)}
                    className="rounded bg-gray-700 border-gray-600 text-indigo-600"
                  />
                  <span className="text-gray-300">{warning}</span>
                </label>
              ))}
            </div>
          </div>

          {/* File Upload */}
          <div className="bg-gray-800 p-6 rounded-lg"> <label className="block text-sm font-medium text-gray-300 mb-2">
              File
            </label>
            <input
              type="file"
              onChange={handleFileChange}
              className="w-full rounded-md bg-gray-700 border-gray-600 text-white"
              required
            />
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            className="w-full rounded-md bg-indigo-600 text-white py-2 px-4"
            disabled={loading}
          >
            {loading ? 'Loading...' : 'Add Content'}
          </button>
        </form>
      </div>
    </AdminLayout>
  );
};

export default AddContentPage;
