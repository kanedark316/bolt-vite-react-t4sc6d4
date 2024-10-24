import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import HomePage from './pages/HomePage';
import LoginPage from './pages/LoginPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ConfirmationPage from './pages/ConfirmationPage';
import RegisterPage from './pages/RegisterPage';
import TVShowsPage from './pages/TVShowsPage';
import MoviesPage from './pages/MoviesPage';
import LivePage from './pages/LivePage';

// Admin Pages
import AdminLoginPage from './admin/pages/AdminLoginPage';
import AdminDashboardPage from './admin/pages/AdminDashboardPage';
import AddContentPage from './admin/pages/AddContentPage';
import ManageAdminsPage from './admin/pages/ManageAdminsPage';

// Protected Route Component
const ProtectedAdminRoute = ({ children }) => {
  const adminToken = localStorage.getItem('adminToken');
  if (!adminToken) {
    return <Navigate to="/admin/login" />;
  }
  return children;
};

function App() {
  return (
    <Router>
      <Routes>
        {/* User Routes */}
        <Route path="/" element={<HomePage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/confirm" element={<ConfirmationPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/tv-shows" element={<TVShowsPage />} />
        <Route path="/movies" element={<MoviesPage />} />
        <Route path="/ppv" element={<LivePage />} />

        {/* Admin Routes */}
        <Route path="/admin/login" element={<AdminLoginPage />} />
        <Route
          path="/admin/dashboard"
          element={
            <ProtectedAdminRoute>
              <AdminDashboardPage />
            </ProtectedAdminRoute>
          }
        />
        <Route
          path="/admin/add"
          element={
            <ProtectedAdminRoute>
              <AddContentPage />
            </ProtectedAdminRoute>
          }
        />
        <Route
          path="/admin/manage-admins"
          element={
            <ProtectedAdminRoute>
              <ManageAdminsPage />
            </ProtectedAdminRoute>
          }
        />
      </Routes>
    </Router>
  );
}

export default App;