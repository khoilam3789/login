import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { AuthService, AuthResponse } from '../services/auth.service';

interface User {
  id: string;
  email: string;
}

interface AuthContextType {
  user: User | null;
  dek: CryptoKey | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, masterPassword: string) => Promise<void>;
  register: (email: string, masterPassword: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [dek, setDek] = useState<CryptoKey | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check if user is already logged in
    const checkAuth = async () => {
      const token = AuthService.getToken();
      if (token) {
        // Token exists but we need DEK from login
        // For now, just set loading to false
        setIsLoading(false);
      } else {
        setIsLoading(false);
      }
    };

    checkAuth();
  }, []);

  const login = async (email: string, masterPassword: string) => {
    try {
      setIsLoading(true);
      const { authResponse, dek: userDek } = await AuthService.login({
        email,
        masterPassword
      });

      setUser(authResponse.user);
      setDek(userDek);
    } catch (error: any) {
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (email: string, masterPassword: string) => {
    try {
      setIsLoading(true);
      await AuthService.register({
        email,
        masterPassword
      });
      setIsLoading(false);
      // Don't auto login - user needs to verify email first
    } catch (error: any) {
      setIsLoading(false);
      throw error;
    }
  };

  const logout = async () => {
    try {
      await AuthService.logout();
    } finally {
      setUser(null);
      setDek(null);
    }
  };

  const value: AuthContextType = {
    user,
    dek,
    isAuthenticated: !!user && !!dek,
    isLoading,
    login,
    register,
    logout
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export default AuthContext;
