import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { api } from '../services/api';
import { User } from '../types';

interface AuthContextType {
  user: User | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  changePassword: (current: string, newPass: string) => Promise<void>;
  isLoading: boolean;
  forceChange: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [forceChange, setForceChange] = useState(false);

  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem('access_token');
      if (token) {
        try {
          const userData = await api.getCurrentUser();
          setUser(userData);
          setForceChange(userData.force_change);
        } catch {
          api.setToken(null);
        }
      }
      setIsLoading(false);
    };
    initAuth();
  }, []);

  const login = async (username: string, password: string) => {
    const data = await api.login(username, password);
    const userData = await api.getCurrentUser();
    setUser(userData);
    setForceChange(data.force_change);
  };

  const logout = async () => {
    try { await api.logout(); }
    finally { setUser(null); setForceChange(false); }
  };

  const changePassword = async (current: string, newPass: string) => {
    await api.changePassword(current, newPass);
    const userData = await api.getCurrentUser();
    setUser(userData);
    setForceChange(false);
  };

  const value = {
    user,
    login,
    logout,
    changePassword,
    isLoading,
    forceChange,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
