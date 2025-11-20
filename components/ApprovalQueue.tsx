import React, { useState, useEffect, useCallback } from 'react';
import { getPendingApprovals, approveItem, rejectItem } from '../services/apiService';
import { User } from '../types';
import Icon from './common/Icon';

interface ApprovalItem {
    id: number;
    name: string;
    itemType: 'equipment' | 'license';
}

interface ApprovalQueueProps {
    currentUser: User;
    onAction: () => void; // Callback to refresh parent data
}

const RejectionModal: React.FC<{
    item: ApprovalItem;
    onClose: () => void;
    onConfirm: (reason: string) => void;
    isProcessing: boolean;
}> = ({ item, onClose, onConfirm, isProcessing }) => {
    const [reason, setReason] = useState('');

    const handleSubmit = () => {
        if (!reason.trim()) {
            alert('Por favor, insira um motivo para a rejeição.');
            return;
        }
        onConfirm(reason);
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex justify-center items-center z-[70] p-4">
            <div className="bg-white dark:bg-dark-card rounded-lg shadow-xl w-full max-w-md">
                <div className="p-6">
                    <h3 className="text-xl font-bold text-brand-dark dark:text-dark-text-primary">Rejeitar Solicitação</h3>
                    <p className="mt-2 text-gray-600 dark:text-dark-text-secondary">
                        Você está rejeitando a solicitação para: <strong>{item.name}</strong>. Por favor, forneça um motivo.
                    </p>
                    <textarea
                        value={reason}
                        onChange={(e) => setReason(e.target.value)}
                        rows={4}
                        className="mt-4 w-full p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800"
                        placeholder="Ex: Informação de patrimônio incorreta."
                    ></textarea>
                </div>
                <div className="p-4 bg-gray-50 dark:bg-dark-card/50 border-t dark:border-dark-border flex justify-end gap-3">
                    <button onClick={onClose} className="bg-gray-500 text-white px-4 py-2 rounded hover:bg-gray-600">Cancelar</button>
                    <button onClick={handleSubmit} disabled={isProcessing} className="bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700 disabled:bg-gray-400">
                        {isProcessing ? 'Rejeitando...' : 'Confirmar Rejeição'}
                    </button>
                </div>
            </div>
        </div>
    );
};


const ApprovalQueue: React.FC<ApprovalQueueProps> = ({ currentUser, onAction }) => {
    const [approvals, setApprovals] = useState<ApprovalItem[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [isProcessing, setIsProcessing] = useState<number | null>(null);
    const [itemToReject, setItemToReject] = useState<ApprovalItem | null>(null);

    const fetchApprovals = useCallback(async () => {
        setIsLoading(true);
        try {
            const data = await getPendingApprovals();
            setApprovals(data);
        } catch (error) {
            console.error("Failed to fetch pending approvals", error);
        } finally {
            setIsLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchApprovals();
    }, [fetchApprovals]);

    const handleApprove = async (item: ApprovalItem) => {
        setIsProcessing(item.id);
        try {
            await approveItem(item.itemType, item.id, currentUser.username);
            await fetchApprovals(); 
            onAction(); 
        } catch (error) {
            console.error(`Failed to approve ${item.itemType}`, error);
            alert("Falha ao aprovar o item.");
        } finally {
            setIsProcessing(null);
        }
    };

    const handleReject = (item: ApprovalItem) => {
        setItemToReject(item);
    };

    const confirmRejection = async (reason: string) => {
        if (!itemToReject) return;
        
        setIsProcessing(itemToReject.id);
        try {
            await rejectItem(itemToReject.itemType, itemToReject.id, currentUser.username, reason);
            setItemToReject(null);
            await fetchApprovals();
            onAction();
        } catch (error) {
            console.error(`Failed to reject ${itemToReject.itemType}`, error);
            alert("Falha ao rejeitar o item.");
        } finally {
            setIsProcessing(null);
        }
    };

    if (isLoading) {
        return (
            <div className="bg-white dark:bg-dark-card p-6 rounded-lg shadow-md">
                <h3 className="text-xl font-semibold mb-4 text-brand-dark dark:text-dark-text-primary">Carregando aprovações...</h3>
            </div>
        );
    }
    
    if (approvals.length === 0) {
        return null;
    }

    return (
        <>
            <div className="bg-white dark:bg-dark-card p-6 rounded-lg shadow-md border-l-4 border-yellow-400 animate-fade-in">
                <h3 className="text-xl font-semibold mb-4 text-brand-dark dark:text-dark-text-primary">Solicitações Pendentes de Aprovação ({approvals.length})</h3>
                <div className="space-y-3 max-h-64 overflow-y-auto pr-2">
                    {approvals.map(item => (
                        <div key={`${item.itemType}-${item.id}`} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-dark-bg rounded-md">
                            <div>
                                <span className={`text-xs font-bold uppercase py-1 px-2 rounded-md mr-3 ${item.itemType === 'equipment' ? 'bg-blue-200 text-blue-800' : 'bg-green-200 text-green-800'}`}>
                                    {item.itemType === 'equipment' ? 'Equip.' : 'Licença'}
                                </span>
                                <span className="text-gray-800 dark:text-dark-text-primary">{item.name}</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <button 
                                    onClick={() => handleApprove(item)} 
                                    disabled={isProcessing === item.id}
                                    className="p-2 text-green-600 hover:bg-green-100 dark:hover:bg-green-900/50 rounded-full disabled:opacity-50"
                                    title="Aprovar"
                                >
                                    <Icon name="Check" size={18} />
                                </button>
                                <button 
                                    onClick={() => handleReject(item)} 
                                    disabled={isProcessing === item.id}
                                    className="p-2 text-red-600 hover:bg-red-100 dark:hover:bg-red-900/50 rounded-full disabled:opacity-50"
                                    title="Rejeitar"
                                >
                                    <Icon name="X" size={18} />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
            {itemToReject && (
                <RejectionModal
                    item={itemToReject}
                    onClose={() => setItemToReject(null)}
                    onConfirm={confirmRejection}
                    isProcessing={isProcessing === itemToReject.id}
                />
            )}
        </>
    );
};

export default ApprovalQueue;