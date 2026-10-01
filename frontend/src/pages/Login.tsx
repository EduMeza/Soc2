import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export const Login: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage('');
    setIsLoading(true);
    try {
      await login(username, password);
      navigate('/dashboard');
    } catch (error: any) {
      setMessage(error.message || 'Error en login');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center">
      <form onSubmit={handleLogin} className="bg-slate-900 border border-slate-800 rounded-3xl p-10 w-full max-w-md shadow-2xl">
        <h1 className="text-3xl font-extrabold text-slate-50 mb-8 text-center">SOC Login</h1>
        <div className="mb-4">
          <label className="block text-sm font-medium text-slate-300 mb-1">Usuario</label>
          <input aria-label="Usuario" autoComplete="username" type="text" value={username} onChange={(e) => setUsername(e.target.value)} className="w-full px-4 py-2 rounded-lg bg-slate-900 border border-slate-600 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Usuario" />
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium text-slate-300 mb-1">Contraseña</label>
          <input aria-label="Contraseña" autoComplete="current-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full px-4 py-2 rounded-lg bg-slate-900 border border-slate-600 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Contraseña" />
        </div>
        <button type="submit" disabled={isLoading} className="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-semibold py-2 rounded-lg transition disabled:opacity-50">
          {isLoading ? 'Iniciando...' : 'Iniciar sesión'}
        </button>
        {message && <p className="mt-3 text-sm text-amber-400 text-center">{message}</p>}
      </form>
    </div>
  );
};
