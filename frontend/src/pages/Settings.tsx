import React, { useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import { ScheduleSettings } from '../components/ScheduleSettings';

export const Settings: React.FC = () => {
  const { user, forceChange, changePassword } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setMessage('Las contraseñas no coinciden');
      return;
    }
    if (newPassword.length < 8) {
      setMessage('La contraseña debe tener al menos 8 caracteres');
      return;
    }
    setIsLoading(true);
    setMessage('');
    try {
      await changePassword(currentPassword, newPassword);
      setMessage('Contraseña cambiada exitosamente');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error: any) {
      setMessage(error.message || 'Error al cambiar contraseña');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-8">
      <div>
        <h2 className="text-2xl font-extrabold text-white">Configuración</h2>
        <p className="text-slate-400 text-sm">Preferencias y seguridad de la cuenta</p>
      </div>

      {forceChange && (
        <div className="bg-amber-900/30 border border-amber-700 rounded-xl p-4 mb-6">
          <div className="flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
            <div>
              <p className="font-bold text-amber-300">Cambio de contraseña obligatorio</p>
              <p className="text-sm text-amber-400">Es tu primer acceso. Debes cambiar la contraseña inicial.</p>
            </div>
          </div>
        </div>
      )}

      <section className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl space-y-6">
        <h3 className="text-xl font-extrabold text-white">Cambiar Contraseña</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Contraseña actual</label>
            <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-600 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Contraseña actual" />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Nueva contraseña</label>
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-600 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Nueva contraseña (mín. 8 caracteres)" minLength={8} />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1">Confirmar nueva contraseña</label>
            <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-600 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500" placeholder="Confirmar nueva contraseña" minLength={8} />
          </div>
          <button onClick={handleChangePassword} disabled={isLoading} className="w-full bg-amber-600 hover:bg-amber-700 text-white font-semibold py-2 rounded-lg transition disabled:opacity-50">
            {isLoading ? 'Cambiando...' : 'Cambiar contraseña'}
          </button>
        </div>
        {message && <p className={`text-sm ${message.includes('Error') || message.includes('no coinciden') || message.includes('8 caracteres') ? 'text-red-400' : 'text-emerald-400'}`}>{message}</p>}
      </section>

      {!forceChange && <ScheduleSettings />}

      <section className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl">
        <h3 className="text-xl font-extrabold text-white mb-4">Información de la cuenta</h3>
        <div className="space-y-2 text-slate-300">
           <p><strong>Usuario:</strong> {user?.username}</p>
          <p><strong>Tipo:</strong> Cuenta SOC local</p>
          <p><strong>Estado:</strong> <span className="text-emerald-400">Activo</span></p>
        </div>
      </section>
    </div>
  );
};

export default Settings;
