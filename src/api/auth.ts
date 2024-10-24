import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

const authAPI = {
  login: async (email: string, password: string) => {
    try {
      const response = await axios.post(`${API_URL}/auth/login`, { email, password });
      if (response.data.token) {
        localStorage.setItem('token', response.data.token);
      }
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Login failed');
    }
  },

  register: async (username: string, email: string, password: string) => {
    try {
      const response = await axios.post(`${API_URL}/auth/register`, { 
        username, 
        email, 
        password 
      });
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Registration failed');
    }
  },

  getUserInfo: async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API_URL}/users/me`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Failed to fetch user info');
    }
  },

  updateUserInfo: async (userData) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.put(`${API_URL}/users/me`, userData, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Failed to update user info');
    }
  },

  updateSubscription: async (plan: string) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post(
        `${API_URL}/users/subscription`,
        { plan },
        { headers: { Authorization: `Bearer ${token}` }}
      );
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Failed to update subscription');
    }
  },

  confirmEmail: async (email: string, code: string) => {
    try {
      const response = await axios.post(`${API_URL}/auth/confirm`, { email, code });
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Email confirmation failed');
    }
  },

  forgotPassword: async (email: string) => {
    try {
      const response = await axios.post(`${API_URL}/auth/forgot-password`, { email });
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Password reset request failed');
    }
  },

  changePassword: async (currentPassword: string, newPassword: string) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.put(
        `${API_URL}/users/password`,
        { currentPassword, newPassword },
        { headers: { Authorization: `Bearer ${token}` }}
      );
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Password change failed');
    }
  }
};

export default authAPI;