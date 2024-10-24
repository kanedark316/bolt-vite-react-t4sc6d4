import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import authAPI from '../api/auth';
import AuthCard from '../components/AuthCard';
import FormInput from '../components/FormInput';

const ForgotPasswordPage = () => {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setMessage('');

    try {
      const response = await authAPI.forgotPassword(email);
      setMessage(response.message || 'Check your email for further instructions.');
      setTimeout(() => navigate('/login'), 5000);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'An error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthCard title="Reset Password">
      {message && (
        <div className={`p-3 rounded-md text-sm ${
          message.includes('error')
            ? 'bg-red-50 text-red-700'
            : 'bg-green-50 text-green-700'
        }`}>
          {message}
        </div>
      )}
      <form onSubmit={handleSubmit} className="space-y-6">
        <FormInput
          id="email"
          label="Email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <button
          type="submit"
          disabled={isLoading}
          className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:bg-gray-400 disabled:cursor-not-allowed"
        >
          {isLoading ? 'Processing...' : 'Reset Password'}
        </button>
      </form>
    </AuthCard>
  );
};

export default ForgotPasswordPage;