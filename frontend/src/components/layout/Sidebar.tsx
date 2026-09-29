import React, { useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

const menu = [
  ['/dashboard', 'Resumen', '◫'], ['/import', 'Importar CSV', '↥'],
  ['/events', 'Eventos', '≡'], ['/correlations', 'Correlaciones', '⛓'],
  ['/timeline', 'Línea temporal', '◷'], ['/mitre', 'MITRE ATT&CK', '◎'],
  ['/geoip', 'Mapa GeoIP', '⌖'], ['/graph', 'Relaciones', '◇'],
  ['/reports', 'Reportes', '▤'], ['/history', 'Historial', '↺'],
  ['/settings', 'Configuración', '⚙'],
];

export const Sidebar: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  return (
    <aside className={`soc-sidebar ${collapsed ? 'is-collapsed' : ''}`}>
      <NavLink to="/dashboard" className="sidebar-brand" aria-label="SOC 24x7 - Inicio">
        <span className="brand-mark">S</span><span className="sidebar-label">SOC <strong>24x7</strong><small>Security operations</small></span>
      </NavLink>
      <nav className="sidebar-nav" aria-label="Navegación principal">
        {menu.map(([path, label, icon]) => <NavLink key={path} to={path} title={label} aria-label={label} className={({ isActive }) => `sidebar-link ${isActive ? 'is-active' : ''}`}>
          <span className="sidebar-icon" aria-hidden="true">{icon}</span><span className="sidebar-label">{label}</span>
        </NavLink>)}
      </nav>
      <div className="sidebar-footer">
        <span className="sidebar-label text-sm text-slate-400">{user?.username || 'Analista SOC'}</span>
        <button className="sidebar-link w-full" title="Cerrar sesión" onClick={() => { logout(); navigate('/login'); }}><span className="sidebar-icon">↪</span><span className="sidebar-label">Cerrar sesión</span></button>
        <button className="sidebar-toggle" onClick={() => setCollapsed(!collapsed)} aria-expanded={!collapsed} aria-label={collapsed ? 'Expandir menú' : 'Contraer menú'}>{collapsed ? '»' : '«'}<span className="sidebar-label">Contraer menú</span></button>
      </div>
    </aside>
  );
};
export default Sidebar;
