import React, { useState } from 'react';
import { User } from '../types';
import Icon from './common/Icon';
import { verify2FA } from '../services/apiService';

interface TwoFactorAuthProps {
  user: User;
  onVerificationSuccess: (user: User) => void;
  onCancel: () => void;
}

const TwoFactorAuth: React.FC<TwoFactorAuthProps> = ({ user, onVerificationSuccess, onCancel }) => {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (token.length !== 6) {
        setError("O código deve ter 6 dígitos.");
        return;
    }
    setIsLoading(true);
    setError('');
    try {
      // A API simulada irá validar o token
      const verifiedUser = await verify2FA(user.id, token);
      onVerificationSuccess(verifiedUser);
    } catch (err: any) {
      if (err instanceof TypeError && err.message === 'Failed to fetch') {
        setError('Não foi possível conectar ao servidor. Verifique se a API está em execução.');
      } else {
        setError(err.message || 'Código de verificação inválido.');
      }
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    // Permite apenas dígitos e limita o comprimento
    const value = e.target.value.replace(/\D/g, '');
    if (value.length <= 6) {
        setToken(value);
    }
  }

  return (
    <div className="relative min-h-screen flex items-center justify-center bg-gray-100 dark:bg-dark-bg p-4">
      <div className="bg-white dark:bg-dark-card p-8 rounded-lg shadow-lg w-full max-w-md text-center">
        <div className="inline-flex items-center justify-center bg-yellow-100 dark:bg-yellow-900/50 text-yellow-600 dark:text-yellow-300 rounded-full p-3 mb-4">
            <Icon name="ShieldAlert" size={32} />
        </div>
        <h1 className="text-2xl font-bold text-brand-dark dark:text-dark-text-primary">Verificação de Dois Fatores</h1>
        <p className="text-gray-500 dark:text-dark-text-secondary mt-2">
            Por segurança, insira o código do seu aplicativo autenticator.
        </p>
        
        {error && <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative my-4 text-left" role="alert">{error}</div>}

        <form onSubmit={handleVerify}>
            <div className="my-6">
                <label className="block text-gray-700 dark:text-dark-text-secondary text-sm font-bold mb-2" htmlFor="token">
                    Código de 6 dígitos
                </label>
                <input
                    id="token"
                    type="text"
                    value={token}
                    onChange={handleInputChange}
                    className="shadow appearance-none border dark:border-dark-border rounded w-full py-3 px-3 bg-white dark:bg-gray-800 text-gray-700 dark:text-dark-text-primary text-center text-3xl tracking-[0.5em] leading-tight focus:outline-none focus:shadow-outline"
                    placeholder="_ _ _ _ _ _"
                    autoFocus
                />
            </div>
            <div className="flex flex-col items-center justify-between gap-4">
                <button
                    type="submit"
                    disabled={isLoading}
                    className="bg-brand-primary hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full transition-colors disabled:bg-gray-400"
                >
                {isLoading ? 'Verificando...' : 'Verificar'}
                </button>
                <button
                    type="button"
                    onClick={onCancel}
                    className="text-sm text-gray-600 dark:text-dark-text-secondary hover:underline"
                >
                    Cancelar e voltar
                </button>
            </div>
        </form>
      </div>
    </div>
  );
};

export default TwoFactorAuth;