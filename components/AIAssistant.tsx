import React, { useState, useEffect } from 'react';
import { getEquipment, generateAiReport } from '../services/apiService';
import { Equipment, User } from '../types';
import Icon from './common/Icon';

const AIAssistant: React.FC<{ currentUser: User }> = ({ currentUser }) => {
    const [query, setQuery] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [report, setReport] = useState<Equipment[] | null>(null);
    const [error, setError] = useState('');
    const [inventoryData, setInventoryData] = useState<Equipment[]>([]);
    const [isDataLoading, setIsDataLoading] = useState(true);

    useEffect(() => {
        const loadInventory = async () => {
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
    }, [currentUser]);


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

    const exampleQueries = [
        "Liste todos os equipamentos do setor FINANCEIRO com garantia expirada.",
        "Mostre todos os notebooks da marca Dell.",
        "Quais equipamentos foram comprados em 2023?",
        "Encontre todos os servidores em manutenção.",
    ];

    return (
        <div className="bg-white dark:bg-dark-card p-4 sm:p-6 rounded-lg shadow-md">
            <h2 className="text-2xl font-bold text-brand-dark dark:text-dark-text-primary mb-4">Assistente de IA para Relatórios</h2>
            <p className="text-gray-600 dark:text-dark-text-secondary mb-6">
                Use linguagem natural para gerar relatórios complexos do seu inventário. O assistente usará a IA do Gemini para filtrar e apresentar os dados.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 mb-4">
                <input
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Ex: 'Liste todos os monitores do setor de TI'"
                    className="flex-grow p-3 border dark:border-dark-border rounded-lg focus:ring-2 focus:ring-brand-primary bg-white dark:bg-gray-800 text-gray-800 dark:text-dark-text-primary"
                    disabled={isLoading || isDataLoading}
                    onKeyPress={(e) => e.key === 'Enter' && handleGenerateReport()}
                />
                <button
                    onClick={handleGenerateReport}
                    disabled={isLoading || isDataLoading}
                    className="bg-brand-primary text-white px-6 py-3 rounded-lg hover:bg-blue-700 disabled:bg-gray-400 flex items-center justify-center gap-2"
                >
                    {isLoading || isDataLoading ? (
                        <>
                            <Icon name="LoaderCircle" className="animate-spin" size={20} />
                            <span>{isDataLoading ? 'Carregando...' : 'Gerando...'}</span>
                        </>
                    ) : (
                        <>
                            <Icon name="Sparkles" size={20} />
                            <span>Gerar Relatório</span>
                        </>
                    )}
                </button>
            </div>
            
            {error && <div className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-4" role="alert"><p>{error}</p></div>}
            
            {!report && !isLoading && (
                <div>
                    <h4 className="text-md font-semibold text-gray-700 dark:text-dark-text-secondary mb-2">Exemplos de consultas:</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
                        {exampleQueries.map((ex, i) => (
                             <button 
                                key={i} 
                                onClick={() => setQuery(ex)}
                                className="text-left p-2 bg-gray-50 dark:bg-dark-bg rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                            >
                                <p className="text-gray-600 dark:text-dark-text-secondary">"{ex}"</p>
                            </button>
                        ))}
                    </div>
                </div>
            )}


            {report && (
                <div className="mt-6">
                    <h3 className="text-xl font-semibold mb-4 text-brand-dark dark:text-dark-text-primary">Resultado do Relatório ({report.length} itens)</h3>
                    {report.length > 0 ? (
                        <div className="overflow-x-auto border dark:border-dark-border rounded-lg">
                            <table className="w-full text-sm text-left text-gray-700 dark:text-dark-text-secondary">
                                <thead className="text-xs text-gray-800 dark:text-dark-text-primary uppercase bg-gray-100 dark:bg-gray-900/50">
                                    <tr>
                                        <th scope="col" className="px-6 py-3">Equipamento</th>
                                        <th scope="col" className="px-6 py-3">Serial</th>
                                        <th scope="col" className="px-6 py-3">Usuário</th>
                                        <th scope="col" className="px-6 py-3">Status</th>
                                        <th scope="col" className="px-6 py-3">Setor</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {report.map(item => (
                                        <tr key={item.id} className="bg-white dark:bg-dark-card border-b dark:border-dark-border hover:bg-gray-50 dark:hover:bg-gray-700">
                                            <td className="px-6 py-4 font-medium text-gray-900 dark:text-dark-text-primary">{item.equipamento}</td>
                                            <td className="px-6 py-4">{item.serial}</td>
                                            <td className="px-6 py-4">{item.usuarioAtual || 'N/A'}</td>
                                            <td className="px-6 py-4">{item.status}</td>
                                            <td className="px-6 py-4">{item.setor}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="text-center py-10 text-gray-500 dark:text-dark-text-secondary">
                            <Icon name="SearchX" size={48} className="mx-auto text-gray-400 mb-4" />
                            <p>A IA não encontrou nenhum resultado para sua consulta.</p>
                        </div>
                    )}
                </div>
            )}

        </div>
    );
};

export default AIAssistant;