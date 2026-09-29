import React from 'react';
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { useAuth } from '../../hooks/useAuth';

export const MainLayout: React.FC = () => {
  const { user, isLoading } = useAuth();

  if (!user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="flex items-start">
        <Sidebar />
        <div className="min-w-0 flex-1">
          <Header />
          <main className="p-4 md:p-6 xl:p-8 space-y-8 max-w-[1800px] mx-auto">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
};
