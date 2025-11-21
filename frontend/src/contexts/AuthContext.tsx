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
    // Restore auth state from localStorage on mount
    const restoreAuth = async () => {
      try {
        const token = AuthService.getToken();
        const storedUser = localStorage.getItem('user');
        const storedDekRaw = localStorage.getItem('dekRaw');

        if (token && storedUser && storedDekRaw) {
          // Re-import DEK from stored raw key
          const dekArrayBuffer = Uint8Array.from(atob(storedDekRaw), c => c.charCodeAt(0));
          const importedDek = await crypto.subtle.importKey(
            'raw',
            dekArrayBuffer,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
          );

          setUser(JSON.parse(storedUser));
          setDek(importedDek);
        }
      } catch (error) {
        console.error('Failed to restore auth:', error);
        // Clear invalid data
        localStorage.removeItem('user');
        localStorage.removeItem('dekRaw');
      } finally {
        setIsLoading(false);
      }
    };

    restoreAuth();
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

      // Persist auth state to localStorage
      localStorage.setItem('user', JSON.stringify(authResponse.user));
      
      // Export DEK to raw format and store
      const dekRaw = await crypto.subtle.exportKey('raw', userDek);
      const dekBase64 = btoa(String.fromCharCode(...new Uint8Array(dekRaw)));
      localStorage.setItem('dekRaw', dekBase64);
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
      
      // Clear persisted auth state
      localStorage.removeItem('user');
      localStorage.removeItem('dekRaw');
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
