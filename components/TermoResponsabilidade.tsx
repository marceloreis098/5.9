import React, { useState, useEffect, useMemo } from 'react';
import { Equipment, User } from '../types';
import Icon from './common/Icon';
import { getTermoTemplates } from '../services/apiService';

interface TermoProps {
    equipment: Equipment;
    user: User;
    onClose: () => void;
    companyName: string;
    termoType: 'entrega' | 'devolucao';
}

const TermoResponsabilidade: React.FC<TermoProps> = ({ equipment, user, onClose, companyName, termoType }) => {
    const [template, setTemplate] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        const fetchTemplates = async () => {
            setIsLoading(true);
            try {
                const templates = await getTermoTemplates();
                if (termoType === 'entrega') {
                    setTemplate(templates.entregaTemplate);
                } else {
                    setTemplate(templates.devolucaoTemplate);
                }
            } catch (error) {
                console.error("Failed to fetch termo templates", error);
                setTemplate("Erro ao carregar o modelo do termo.");
            } finally {
                setIsLoading(false);
            }
        };
        fetchTemplates();
    }, [termoType]);

    const collaboratorName = useMemo(() => {
        return termoType === 'devolucao' ? (equipment.usuarioAnterior || 'Usuário não especificado') : (equipment.usuarioAtual || user.realName);
    }, [termoType, equipment, user]);

    const renderedContent = useMemo(() => {
        if (!template) return '';
        const today = new Date().toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' });
        
        return template
            .replace(/{{USUARIO}}/g, collaboratorName)
            .replace(/{{EQUIPAMENTO}}/g, equipment.equipamento || 'N/A')
            .replace(/{{SERIAL}}/g, equipment.serial || 'N/A')
            .replace(/{{PATRIMONIO}}/g, equipment.patrimonio || 'N/A')
            .replace(/{{EMPRESA}}/g, companyName)
            .replace(/{{DATA}}/g, today)
            .replace(/{{DATA_ENTREGA}}/g, equipment.dataEntregaUsuario ? new Date(equipment.dataEntregaUsuario).toLocaleDateString('pt-BR') : 'N/A')
            .replace(/{{DATA_DEVOLUCAO}}/g, equipment.dataDevolucao ? new Date(equipment.dataDevolucao).toLocaleDateString('pt-BR') : 'N/A');
    }, [template, equipment, collaboratorName, companyName]);

    const title = termoType === 'devolucao' ? "Termo de Devolução de Equipamento" : "Termo de Responsabilidade";

    const handleEmail = () => {
        const subject = `${title} - ${equipment.equipamento}`;
        // Extrai o texto simples do HTML para o corpo do email
        const bodyElement = document.createElement('div');
        bodyElement.innerHTML = renderedContent.replace(/<br\s*\/?>/gi, '\n');
        const textContent = bodyElement.textContent || '';
        
        window.location.href = `mailto:${equipment.emailColaborador || ''}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(textContent.trim())}`;
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-60 flex justify-center items-center z-[60] p-4 print:bg-white print:p-0">
            <div id="termo-modal" className="bg-white dark:bg-dark-card rounded-lg shadow-xl w-full max-w-3xl max-h-[90vh] flex flex-col print:shadow-none print:border print:max-h-full print:rounded-none">
                <div className="p-4 border-b dark:border-dark-border flex justify-between items-center print:hidden">
                    <h3 className="text-lg font-bold text-brand-dark dark:text-dark-text-primary">{title}</h3>
                    <button onClick={onClose} className="text-gray-500 hover:text-gray-800 dark:text-gray-400 dark:hover:text-white">
                        <Icon name="X" size={24} />
                    </button>
                </div>
                <div className="p-8 overflow-y-auto text-gray-800 dark:text-dark-text-primary">
                    {isLoading ? (
                        <div className="flex justify-center items-center h-64">
                            <Icon name="LoaderCircle" className="animate-spin text-brand-primary" size={48} />
                        </div>
                    ) : (
                         <div dangerouslySetInnerHTML={{ __html: renderedContent.replace(/\n/g, '<br />') }} />
                    )}
                </div>
                <div className="p-4 bg-gray-50 dark:bg-dark-card/50 border-t dark:border-dark-border flex justify-end gap-3 print:hidden">
                    <button onClick={handleEmail} className="bg-teal-600 text-white px-4 py-2 rounded-lg hover:bg-teal-700 flex items-center gap-2">
                        <Icon name="Mail" size={16}/> Enviar por E-mail
                    </button>
                    <button onClick={() => window.print()} className="bg-sky-600 text-white px-4 py-2 rounded-lg hover:bg-sky-700 flex items-center gap-2">
                        <Icon name="Printer" size={16}/> Imprimir
                    </button>
                    <button onClick={onClose} className="bg-gray-500 text-white px-4 py-2 rounded-lg hover:bg-gray-600">
                        Fechar
                    </button>
                </div>
            </div>
        </div>
    );
};

export default TermoResponsabilidade;
