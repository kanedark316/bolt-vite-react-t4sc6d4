import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL;

const adminAPI = {
  // Authentication
  login: async (email: string, password: string) => {
    const response = await axios.post(`${API_URL}/admin/login`, { email, password });
    return response.data;
  },

  // Analytics
  getAnalytics: async () => {
    const token = localStorage.getItem('adminToken');
    const response = await axios.get(`${API_URL}/admin/analytics`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  },

  // Content Management
  addContent: async (contentData: any) => {
    const token = localStorage.getItem('adminToken');
    const response = await axios.post(`${API_URL}/admin/content`, contentData, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  },

  uploadToS3: async (file: File, contentType: string) => {
    const token = localStorage.getItem('adminToken');
    
    // Get pre-signed URL
    const { uploadUrl, fileUrl } = await axios.post(
      `${API_URL}/admin/upload-url`,
      { contentType, fileName: file.name },
      { headers: { Authorization: `Bearer ${token}` }}
    ).then(res => res.data);

    // Upload file to S3
    await axios.put(uploadUrl, file, {
      headers: { 'Content-Type': file.type }
    });

    return fileUrl;
  },

  // Content Lists
  getMovies: async () => {
    const token = localStorage.getItem('adminToken');
    const response = await axios.get(`${API_URL}/admin/movies`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  },

  getTVShows: async () => {
    const token = localStorage.getItem('adminToken');
    const response = await axios.get(`${API_URL}/admin/tv-shows`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  },

  getLiveEvents: async () => {
    const token = localStorage.getItem('adminToken');
    const response = await axios.get(`${API_URL}/admin/live-events`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    return response.data;
  }
};

export default adminAPI;