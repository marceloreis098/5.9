import React, { useState, useEffect } from 'react';
import { QRCodeCanvas as QRCode } from 'qrcode.react';
import { User } from '../types';
import Icon from './common/Icon';
import { generate2FASecret, enable2FA } from '../services/apiService';

interface TwoFactorSetupProps {
  user: User;
  onSetupSuccess: (user: User) => void;
  onCancel: () => void;
}

const TwoFactorSetup: React.FC<TwoFactorSetupProps> = ({ user, onSetupSuccess, onCancel }) => {
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const generateSecret = async () => {
      setIsLoading(true);
      setError('');
      try {
        const data = await generate2FASecret(user.id);
        setSecret(data.secret);
        setQrCodeUrl(data.qrCodeUrl);
      } catch (err: any) {
        setError(err.message || 'Falha ao gerar o QR Code para 2FA.');
      } finally {
        setIsLoading(false);
      }
    };
    generateSecret();
  }, [user.id]);

  const handleVerifyAndEnable = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!secret || token.length !== 6) {
      setError("Por favor, insira um código válido de 6 dígitos.");
      return;
    }
    setIsLoading(true);
    setError('');
    try {
      await enable2FA(user.id, token);
      onSetupSuccess(user);
    } catch (err: any) {
      setError(err.message || 'Código de verificação inválido. Tente novamente.');
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, '');
    if (value.length <= 6) {
      setToken(value);
    }
  };

  return (
    <div className="relative min-h-screen flex items-center justify-center bg-gray-100 dark:bg-dark-bg p-4">
      <div className="bg-white dark:bg-dark-card p-8 rounded-lg shadow-lg w-full max-w-lg text-center">
        <Icon name="ShieldCheck" size={48} className="mx-auto text-brand-primary mb-4" />
        <h1 className="text-2xl font-bold text-brand-dark dark:text-dark-text-primary">Configure a Autenticação de Dois Fatores (2FA)</h1>
        <p className="text-gray-600 dark:text-dark-text-secondary mt-2">
          Para aumentar a segurança da sua conta, a configuração do 2FA é obrigatória para continuar.
        </p>

        {isLoading && !error && (
            <div className="my-8 flex flex-col items-center">
                <Icon name="LoaderCircle" className="animate-spin text-brand-primary" size={48} />
                <p className="mt-4 text-gray-500">Gerando seu código de segurança...</p>
            </div>
        )}

        {error && <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative my-6 text-left" role="alert">{error}</div>}

        {!isLoading && qrCodeUrl && secret && (
          <div className="my-6 space-y-6 text-left animate-fade-in">
            <div>
              <p className="font-semibold text-gray-800 dark:text-dark-text-primary">1. Escaneie este QR Code com seu aplicativo autenticador (Google Authenticator, Authy, etc.).</p>
              <div className="mt-2 p-4 border dark:border-dark-border rounded-lg bg-white inline-block">
                <QRCode value={qrCodeUrl} size={160} level="H" />
              </div>
            </div>
            <div>
              <p className="font-semibold text-gray-800 dark:text-dark-text-primary">2. Se não puder escanear, insira esta chave manualmente:</p>
              <p className="mt-1 p-2 bg-gray-100 dark:bg-gray-800 rounded-md font-mono text-center tracking-widest">{secret}</p>
            </div>
            <div>
              <p className="font-semibold text-gray-800 dark:text-dark-text-primary">3. Insira o código de 6 dígitos gerado pelo aplicativo.</p>
              <form onSubmit={handleVerifyAndEnable} className="mt-2">
                <input
                  id="token"
                  type="text"
                  value={token}
                  onChange={handleInputChange}
                  className="shadow appearance-none border dark:border-dark-border rounded w-full py-3 px-3 bg-white dark:bg-gray-800 text-gray-700 dark:text-dark-text-primary text-center text-3xl tracking-[0.5em] leading-tight focus:outline-none focus:shadow-outline"
                  placeholder="_ _ _ _ _ _"
                  autoFocus
                />
                <button
                  type="submit"
                  disabled={isLoading}
                  className="mt-4 bg-brand-primary hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full transition-colors disabled:bg-gray-400"
                >
                  {isLoading ? 'Verificando...' : 'Verificar e Ativar'}
                </button>
              </form>
            </div>
          </div>
        )}

        <div className="mt-6">
            <button
                type="button"
                onClick={onCancel}
                className="text-sm text-gray-600 dark:text-dark-text-secondary hover:underline"
            >
                Sair
            </button>
        </div>
      </div>
    </div>
  );
};

export default TwoFactorSetup;
