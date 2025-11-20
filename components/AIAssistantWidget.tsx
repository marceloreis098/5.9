import React, { useState, useEffect, useRef } from 'react';
import { getEquipment, generateAiReport } from '../services/apiService';
import { Equipment, User } from '../types';
import Icon from './common/Icon';

const AIAssistantWidget: React.FC<{ currentUser: User }> = ({ currentUser }) => {
    const [isOpen, setIsOpen] = useState(false);
    const [query, setQuery] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [report, setReport] = useState<Equipment[] | null>(null);
    const [error, setError] = useState<React.ReactNode>('');
    const [inventoryData, setInventoryData] = useState<Equipment[]>([]);
    const [isDataLoading, setIsDataLoading] = useState(true);
    const widgetRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const loadInventory = async () => {
            if (!isOpen) return; // Only load data when widget is opened
            setIsDataLoading(true);
            try {
                const data = await getEquipment(currentUser);
                setInventoryData(data);
            } catch (error) {
                console.error("Failed to load inventory for AI assistant", error);
                setError("Não foi possível carregar os dados do inventário para o assistente.");
            } finally {
                setIsDataLoading(false);
            }
        };
        loadInventory();
    }, [currentUser, isOpen]);

    useEffect(() => {
        // Close widget if clicked outside
        const handleClickOutside = (event: MouseEvent) => {
            if (widgetRef.current && !widgetRef.current.contains(event.target as Node)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, []);


    const handleGenerateReport = async () => {
        if (!query.trim()) return;

        setIsLoading(true);
        setError('');
        setReport(null);
        try {
            const result = await generateAiReport(query, inventoryData, currentUser.username);

            if (result.error) {
                setError(result.error);
            } else if (result.reportData) {
                setReport(result.reportData);
            } else {
                setError('A resposta do servidor não continha dados de relatório válidos.');
            }
        } catch (e: any) {
            console.error(e);
            setError(`Falha ao processar a resposta do servidor de IA: ${e.message}`);
        } finally {
            setIsLoading(false);
        }
    };
    
    if (!isOpen) {
        return (
            <button
                onClick={() => setIsOpen(true)}
                className="fixed bottom-6 right-6 bg-brand-primary text-white w-16 h-16 rounded-full shadow-lg flex items-center justify-center hover:bg-blue-700 transition-transform hover:scale-110 z-50"
                title="Assistente de IA"
            >
                <Icon name="Bot" size={28} />
            </button>
        );
    }


    return (
        <div ref={widgetRef} className="fixed bottom-6 right-6 w-full max-w-lg h-[70vh] bg-white dark:bg-dark-card rounded-xl shadow-2xl flex flex-col z-50 animate-fade-in-up">
            <header className="flex items-center justify-between p-4 border-b dark:border-dark-border bg-gray-50 dark:bg-gray-900/50 rounded-t-xl">
                <div className="flex items-center gap-3">
                    <Icon name="Bot" size={24} className="text-brand-primary" />
                    <h3 className="text-lg font-bold text-brand-dark dark:text-dark-text-primary">Assistente de Relatórios</h3>
                </div>
                <button onClick={() => setIsOpen(false)} className="text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-white">
                    <Icon name="X" size={24} />
                </button>
            </header>

            <div className="flex-grow p-4 overflow-y-auto">
                {error && <div className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-4" role="alert">{error}</div>}
                
                {report ? (
                    <div className="space-y-4">
                        <div className="flex justify-between items-center">
                             <h4 className="text-md font-semibold text-brand-dark dark:text-dark-text-primary">Resultados ({report.length} itens)</h4>
                             <button onClick={() => setReport(null)} className="text-sm text-brand-primary hover:underline">Nova consulta</button>
                        </div>
                        {report.length > 0 ? (
                            <div className="space-y-3">
                                {report.map(item => (
                                    <div key={item.id} className="p-3 bg-gray-50 dark:bg-dark-bg border dark:border-dark-border rounded-lg text-xs">
                                        <p className="font-bold">{item.equipamento}</p>
                                        <p><strong>Usuário:</strong> {item.usuarioAtual || 'N/A'}</p>
                                        <p><strong>Serial:</strong> {item.serial || 'N/A'}</p>
                                        <p><strong>Status:</strong> {item.status}</p>
                                    </div>
                                ))}
                            </div>
                        ) : (
                            <div className="text-center py-6 text-gray-500 dark:text-dark-text-secondary">
                                <Icon name="SearchX" size={32} className="mx-auto text-gray-400 mb-2" />
                                <p>Nenhum resultado encontrado.</p>
                            </div>
                        )}
                    </div>
                ) : (
                     <div className="text-center text-gray-500 dark:text-dark-text-secondary">
                        <Icon name="Lightbulb" size={32} className="mx-auto text-yellow-400 mb-2"/>
                        <p>Faça uma pergunta sobre o inventário.</p>
                        <p className="text-xs mt-2">Ex: "Quais notebooks Dell estão em estoque?"</p>
                    </div>
                )}
            </div>

            <footer className="p-4 border-t dark:border-dark-border">
                 <div className="flex gap-2">
                    <input
                        type="text"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Pergunte algo..."
                        className="flex-grow p-3 border dark:border-dark-border rounded-lg bg-white dark:bg-gray-800 text-gray-800 dark:text-dark-text-primary"
                        disabled={isLoading || isDataLoading}
                        onKeyPress={(e) => e.key === 'Enter' && handleGenerateReport()}
                    />
                    <button
                        onClick={handleGenerateReport}
                        disabled={isLoading || isDataLoading || !query.trim()}
                        className="bg-brand-primary text-white p-3 rounded-lg hover:bg-blue-700 disabled:bg-gray-400 flex items-center justify-center"
                    >
                        {isLoading || isDataLoading ? (
                            <Icon name="LoaderCircle" className="animate-spin" size={24} />
                        ) : (
                           <Icon name="Send" size={24} />
                        )}
                    </button>
                </div>
            </footer>
        </div>
    );
};

export default AIAssistantWidget;