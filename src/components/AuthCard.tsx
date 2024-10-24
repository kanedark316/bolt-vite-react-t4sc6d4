import React from 'react';

interface AuthCardProps {
  children: React.ReactNode;
  title: string;
}

const AuthCard: React.FC<AuthCardProps> = ({ children, title }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 flex items-center justify-center px-4 py-12">
      <div className="max-w-md w-full space-y-8 bg-white p-8 rounded-xl shadow-2xl">
        <h2 className="text-3xl font-bold text-center text-gray-900">{title}</h2>
        {children}
      </div>
    </div>
  );
};

export default AuthCard;