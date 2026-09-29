import React from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

export const Header: React.FC = () => {
  const { user } = useAuth();

  return (
    <header className="flex flex-wrap gap-3 items-center justify-between px-4 md:px-8 py-4 bg-slate-900/95 border-b border-slate-800 sticky top-0 z-20 backdrop-blur">
      <div className="flex items-center gap-3">
        <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse" />
        <span className="text-base font-semibold tracking-tight text-white">Centro de operaciones SOC</span>
      </div>
      <nav className="flex gap-2 text-sm font-medium">
        <NavLink to="/import" className="btn-secondary">Importar CSV</NavLink>
        <NavLink to="/reports" className="btn-primary">Reportes</NavLink>
      </nav>
    </header>
  );
};
