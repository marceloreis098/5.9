import React, { useState, useEffect } from 'react';
import { QRCodeCanvas as QRCode } from 'qrcode.react';
import { User } from '../types';
import Icon from './common/Icon';
import { generate2FASecret, enable2FA } from '../services/apiService';

interface Admin2FASetupModalProps {
  user: User;
  onClose: () => void;
  onSuccess: () => void;
}

const Admin2FASetupModal: React.FC<Admin2FASetupModalProps> = ({ user, onClose, onSuccess }) => {
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const generateSecretForUser = async () => {
      setIsLoading(true);
      setError('');
      try {
        const data = await generate2FASecret(user.id);
        setSecret(data.secret);
        setQrCodeUrl(data.qrCodeUrl);
      } catch (err: any) {
        setError(err.message || 'Falha ao gerar o QR Code para o usuário.');
      } finally {
        setIsLoading(false);
      }
    };
    generateSecretForUser();
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
      alert(`2FA ativado com sucesso para ${user.realName}!`);
      onSuccess();
    } catch (err: any) {
      setError(err.message || 'Código de verificação inválido. Tente novamente.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center z-50 p-4">
      <div className="bg-white dark:bg-dark-card rounded-lg shadow-xl w-full max-w-lg max-h-[90vh] flex flex-col">
        <div className="p-6 border-b dark:border-dark-border">
          <h3 className="text-xl font-bold text-brand-dark dark:text-dark-text-primary">
            Configurar 2FA para <span className="text-brand-primary">{user.realName}</span>
          </h3>
        </div>
        <div className="p-6 space-y-4 overflow-y-auto">
          {isLoading && !error && (
            <div className="flex flex-col items-center py-8">
              <Icon name="LoaderCircle" className="animate-spin text-brand-primary" size={48} />
              <p className="mt-4 text-gray-500">Gerando código de segurança para o usuário...</p>
            </div>
          )}

          {error && <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded text-left" role="alert">{error}</div>}

          {!isLoading && qrCodeUrl && secret && (
            <div className="space-y-4 text-left animate-fade-in">
              <div>
                <p className="font-semibold text-gray-800 dark:text-dark-text-primary">1. Peça para {user.realName} escanear este QR Code.</p>
                <div className="mt-2 p-2 border dark:border-dark-border rounded-lg bg-white inline-block">
                  <QRCode value={qrCodeUrl} size={160} level="H" />
                </div>
              </div>
              <div>
                <p className="font-semibold text-gray-800 dark:text-dark-text-primary">2. Se não for possível escanear, forneça esta chave:</p>
                <p className="mt-1 p-2 bg-gray-100 dark:bg-gray-800 rounded-md font-mono text-center tracking-widest">{secret}</p>
              </div>
              <div>
                <p className="font-semibold text-gray-800 dark:text-dark-text-primary">3. Insira o código de 6 dígitos gerado no aplicativo do usuário para ativar.</p>
                <form onSubmit={handleVerifyAndEnable} className="mt-2 flex items-center gap-2">
                  <input
                    type="text"
                    value={token}
                    onChange={(e) => setToken(e.target.value.replace(/\D/g, ''))}
                    maxLength={6}
                    className="flex-grow shadow appearance-none border dark:border-dark-border rounded py-2 px-3 bg-white dark:bg-gray-800 text-gray-700 dark:text-dark-text-primary leading-tight focus:outline-none focus:shadow-outline"
                    placeholder="123456"
                    autoFocus
                  />
                  <button
                    type="submit"
                    disabled={isLoading}
                    className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline transition-colors disabled:bg-gray-400"
                  >
                    {isLoading ? '...' : 'Ativar'}
                  </button>
                </form>
              </div>
            </div>
          )}
        </div>
        <div className="p-4 bg-gray-50 dark:bg-dark-card/50 border-t dark:border-dark-border flex justify-end">
          <button type="button" onClick={onClose} className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">
            Fechar
          </button>
        </div>
      </div>
    </div>
  );
};

export default Admin2FASetupModal;