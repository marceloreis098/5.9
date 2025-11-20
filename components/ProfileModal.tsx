
// Novo arquivo: components/ProfileModal.tsx
import React, { useState, useRef, useEffect } from 'react';
import { QRCodeCanvas as QRCode } from 'qrcode.react';
import { User } from '../types';
import Icon from './common/Icon';
import { generate2FASecret, enable2FA, disable2FA, updateUserProfile } from '../services/apiService';

interface ProfileModalProps {
    user: User;
    onClose: () => void;
    onSave: (updatedUser: User) => void;
}

const ProfileModal: React.FC<ProfileModalProps> = ({ user, onClose, onSave }) => {
    const [realName, setRealName] = useState(user.realName);
    const [avatar, setAvatar] = useState(user.avatarUrl || '');
    const [isSaving, setIsSaving] = useState(false);
    const [error, setError] = useState('');
    const fileInputRef = useRef<HTMLInputElement>(null);

    // 2FA State
    const [is2FAEnabled, setIs2FAEnabled] = useState(user.is2FAEnabled);
    const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null);
    const [secret, setSecret] = useState<string | null>(null);
    const [token, setToken] = useState('');
    const [error2FA, setError2FA] = useState('');
    const [loading2FA, setLoading2FA] = useState(false);

    useEffect(() => {
        // Atualiza o estado interno se o usuário mudar (após salvar, por exemplo)
        setIs2FAEnabled(user.is2FAEnabled);
    }, [user.is2FAEnabled]);
    
    const handlePhotoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (file) {
            if (!file.type.startsWith('image/')) {
                setError('Por favor, selecione um arquivo de imagem válido.');
                return;
            }
            if (file.size > 2 * 1024 * 1024) { // 2MB
                setError('O arquivo é muito grande. O limite é de 2MB.');
                return;
            }
            setError('');
            const reader = new FileReader();
            reader.onloadend = () => {
                setAvatar(reader.result as string);
            };
            reader.readAsDataURL(file);
        }
    };

    const handleSave = async () => {
        setIsSaving(true);
        setError('');
        try {
            const updatedUserFromApi = await updateUserProfile(user.id, { realName, avatarUrl: avatar });
            onSave(updatedUserFromApi);
        } catch (err: any) {
            setError(err.message || 'Falha ao salvar o perfil.');
        } finally {
            setIsSaving(false);
        }
    };

    const handleGenerateSecret = async () => {
        setLoading2FA(true);
        setError2FA('');
        try {
            const data = await generate2FASecret(user.id);
            setSecret(data.secret);
            setQrCodeUrl(data.qrCodeUrl);
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : 'Falha ao gerar o segredo 2FA.';
            setError2FA(message);
        } finally {
            setLoading2FA(false);
        }
    };

    const handleEnable2FA = async () => {
        if (!secret || token.length !== 6) {
            setError2FA("Por favor, insira um código válido de 6 dígitos.");
            return;
        }
        setLoading2FA(true);
        setError2FA('');
        try {
            await enable2FA(user.id, token);
            setIs2FAEnabled(true);
            setQrCodeUrl(null);
            setSecret(null);
            setToken('');
            alert('2FA habilitado com sucesso!');
        } catch (error: any) {
             setError2FA(error.message || 'Código de verificação inválido.');
        } finally {
             setLoading2FA(false);
        }
    };

    const handleDisable2FA = async () => {
        if (!window.confirm("Tem certeza de que deseja desabilitar a autenticação de dois fatores?")) return;
        setLoading2FA(true);
        setError2FA('');
        try {
            await disable2FA(user.id);
            setIs2FAEnabled(false);
            alert('2FA desabilitado com sucesso!');
        } catch (error: any) {
            setError2FA(error.message || 'Falha ao desabilitar 2FA.');
        } finally {
            setLoading2FA(false);
        }
    };

    return (
        <div role="dialog" aria-modal="true" className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center z-50 p-4">
            <div className="bg-white dark:bg-dark-card rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] flex flex-col">
                <div className="p-6 border-b dark:border-dark-border flex justify-between items-center">
                    <h3 className="text-xl font-bold text-brand-dark dark:text-dark-text-primary">Meu Perfil</h3>
                    <button onClick={onClose} className="text-gray-500 hover:text-gray-800"><Icon name="X" size={24} /></button>
                </div>
                
                <div className="p-6 space-y-6 overflow-y-auto">
                    {error && <p className="text-red-500 text-sm">{error}</p>}
                    
                    {/* Profile Info Section */}
                    <div className="flex items-center gap-6">
                        <div className="relative">
                            <img 
                                src={avatar || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.realName)}&background=3498db&color=fff&size=96`} 
                                alt="Avatar" 
                                className="w-24 h-24 rounded-full object-cover border-4 border-gray-200 dark:border-dark-border"
                            />
                            <button 
                                onClick={() => fileInputRef.current?.click()}
                                className="absolute bottom-0 right-0 bg-brand-secondary text-white p-1.5 rounded-full hover:bg-brand-dark transition-colors"
                                title="Alterar foto"
                            >
                                <Icon name="Camera" size={16} />
                            </button>
                            <input 
                                type="file" 
                                ref={fileInputRef} 
                                onChange={handlePhotoChange} 
                                className="hidden"
                                accept="image/png, image/jpeg"
                            />
                        </div>
                        <div className="flex-grow space-y-2">
                             <div>
                                <label className="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary">Nome de Exibição</label>
                                <input 
                                    type="text" 
                                    value={realName} 
                                    onChange={(e) => setRealName(e.target.value)}
                                    className="mt-1 block w-full p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800"
                                />
                            </div>
                             <p className="text-sm text-gray-500 dark:text-dark-text-secondary"><strong>Usuário:</strong> {user.username}</p>
                        </div>
                    </div>
                    
                    {/* Account Details Section */}
                     <div>
                        <h4 className="font-semibold text-gray-800 dark:text-dark-text-primary border-b dark:border-dark-border pb-2 mb-3">Detalhes da Conta</h4>
                        <div className="text-sm space-y-2 text-gray-600 dark:text-dark-text-secondary">
                             <p><strong>Email:</strong> {user.email}</p>
                             <p><strong>Permissão:</strong> {user.role}</p>
                        </div>
                    </div>
                    
                    {/* 2FA Section */}
                    <div>
                        <h4 className="font-semibold text-gray-800 dark:text-dark-text-primary border-b dark:border-dark-border pb-2 mb-3">Segurança</h4>
                        {user.ssoProvider ? (
                            <div className="p-3 bg-blue-50 dark:bg-blue-900/20 border-l-4 border-blue-400 text-sm text-blue-700 dark:text-blue-300">
                                A segurança da sua conta é gerenciada pelo seu provedor de login ({user.ssoProvider}).
                            </div>
                        ) : (
                            <>
                                {error2FA && <p className="text-red-500 mb-4">{error2FA}</p>}
                                {is2FAEnabled ? (
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2 text-green-600 dark:text-green-400 font-semibold">
                                            <Icon name="ShieldCheck" size={20} />
                                            <span>Autenticação de dois fatores (2FA) está ATIVADA.</span>
                                        </div>
                                        <button onClick={handleDisable2FA} disabled={loading2FA} className="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 disabled:bg-gray-400">
                                            {loading2FA ? '...' : 'Desativar'}
                                        </button>
                                    </div>
                                ) : qrCodeUrl ? (
                                    <div className="flex flex-col md:flex-row gap-6 items-center">
                                        <div className="text-center">
                                            <p className="font-semibold mb-2">1. Escaneie o QR Code</p>
                                            <div className="p-2 border dark:border-dark-border rounded-lg bg-white inline-block">
                                               <QRCode value={qrCodeUrl} size={160} level="H" />
                                            </div>
                                        </div>
                                        <div className="flex-1">
                                             <p className="font-semibold mb-2">2. Insira o código de 6 dígitos</p>
                                             <div className="flex items-center gap-2">
                                                <input
                                                    type="text"
                                                    value={token}
                                                    onChange={(e) => setToken(e.target.value)}
                                                    placeholder="123456"
                                                    maxLength={6}
                                                    className="p-2 border dark:border-dark-border rounded-md w-32"
                                                />
                                                <button onClick={handleEnable2FA} disabled={loading2FA} className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 disabled:bg-gray-400">
                                                    {loading2FA ? '...' : 'Ativar'}
                                                </button>
                                             </div>
                                        </div>
                                    </div>
                                ) : (
                                    <button onClick={handleGenerateSecret} disabled={loading2FA} className="bg-brand-primary text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:bg-gray-400">
                                        {loading2FA ? 'Gerando...' : 'Habilitar 2FA'}
                                    </button>
                                )}
                            </>
                        )}
                    </div>
                </div>

                <div className="p-4 bg-gray-50 dark:bg-dark-card/50 border-t dark:border-dark-border flex justify-end gap-3">
                    <button type="button" onClick={onClose} className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">Cancelar</button>
                    <button type="button" onClick={handleSave} disabled={isSaving} className="bg-brand-primary text-white px-4 py-2 rounded hover:bg-blue-700 disabled:bg-gray-400">
                        {isSaving ? 'Salvando...' : 'Salvar Alterações'}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ProfileModal;
