import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import authAPI from '../api/auth';
import AuthCard from '../components/AuthCard';
import FormInput from '../components/FormInput';

const ConfirmationPage = () => {
  const [confirmationCode, setConfirmationCode] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const email = (location.state as any)?.email;

  const handleConfirmation = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const { token } = await authAPI.confirmEmail(email, confirmationCode);
      localStorage.setItem('token', token);
      navigate('/subscription');
    } catch (error) {
      alert(error instanceof Error ? error.message : 'Confirmation failed. Please try again.');
    }
  };

  return (
    <AuthCard title="Confirm Your Email">
      <p className="text-gray-600 text-center mb-6">
        We've sent a confirmation code to {email}. Please enter it below.
      </p>
      <form onSubmit={handleConfirmation} className="space-y-6">
        <FormInput
          id="confirmationCode"
          label="Confirmation Code"
          type="text"
          value={confirmationCode}
          onChange={(e) => setConfirmationCode(e.target.value)}
          required
        />
        <button
          type="submit"
          className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
        >
          Confirm Email
        </button>
      </form>
    </AuthCard>
  );
};

export default ConfirmationPage;