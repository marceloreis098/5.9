
import React, { useState, useEffect, useMemo } from 'react';
import { Equipment, User, UserRole, EquipmentHistory } from '../types';
import { getEquipment, addEquipment, updateEquipment, deleteEquipment, getEquipmentHistory } from '../services/apiService';
import Icon from './common/Icon';
import TermoResponsabilidade from './TermoResponsabilidade';

interface EquipmentFormModalProps {
    equipment: Equipment | null;
    onClose: () => void;
    onSave: () => void;
    currentUser: User;
}

const EquipmentFormModal: React.FC<EquipmentFormModalProps> = ({ equipment, onClose, onSave, currentUser }) => {
    const [formData, setFormData] = useState<Partial<Equipment>>({
        equipamento: '',
        garantia: '',
        patrimonio: '',
        serial: '',
        usuarioAtual: '',
        local: '',
        setor: '',
        dataEntregaUsuario: '',
        status: 'Estoque',
        tipo: '',
        notaCompra: '',
        notaPlKm: '',
        brand: '',
        model: '',
        observacoes: '',
        emailColaborador: '',
        condicaoTermo: 'N/A'
    });
    const [isSaving, setIsSaving] = useState(false);
    const [saveError, setSaveError] = useState('');

    useEffect(() => {
        if (equipment) {
            setFormData({
                ...equipment,
                dataEntregaUsuario: equipment.dataEntregaUsuario ? equipment.dataEntregaUsuario.split('T')[0] : '',
                dataDevolucao: equipment.dataDevolucao ? equipment.dataDevolucao.split('T')[0] : ''
            });
        }
    }, [equipment]);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSaving(true);
        setSaveError('');

        // Basic validation for required fields
        if (!formData.equipamento || !formData.serial) {
            setSaveError('Equipamento e Serial são campos obrigatórios.');
            setIsSaving(false);
            return;
        }

        try {
            if (equipment) {
                await updateEquipment({ ...formData, id: equipment.id } as Equipment, currentUser.username);
            } else {
                await addEquipment(formData as any, currentUser);
                if (currentUser.role !== UserRole.Admin) {
                    alert("Equipamento adicionado com sucesso! Sua solicitação foi enviada para aprovação do administrador.");
                }
            }
            onSave();
            onClose();
        } catch (error: any) {
            console.error("Failed to save equipment", error);
            let message = error.message || "Falha desconhecida ao salvar.";
            
            if (error instanceof TypeError && message === 'Failed to fetch') {
                message = "Erro de conexão com o servidor. Verifique se a API (backend) está rodando na porta 3001.";
            } else if (message.includes('Database error')) {
                // Tenta limpar a mensagem de erro do banco para ficar mais legível se possível
                message = `Erro no Banco de Dados: ${message.replace('Database error: ', '')}`;
            }

            setSaveError(message);
        } finally {
            setIsSaving(false);
        }
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-start sm:items-center z-50 p-4 overflow-y-auto">
            <form onSubmit={handleSubmit} className="bg-white dark:bg-dark-card rounded-lg shadow-xl w-full max-w-4xl flex flex-col max-h-[90vh]">
                <div className="p-6 border-b dark:border-dark-border flex-shrink-0">
                    <h3 className="text-xl font-bold text-brand-dark dark:text-dark-text-primary">{equipment ? 'Editar Equipamento' : 'Novo Equipamento'}</h3>
                </div>
                <div className="p-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 overflow-y-auto">
                    {saveError && (
                        <div className="sm:col-span-3 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative break-words" role="alert">
                            <strong className="font-bold">Erro: </strong>
                            <span className="block sm:inline">{saveError}</span>
                        </div>
                    )}

                    <input type="text" name="equipamento" placeholder="Nome do Equipamento *" value={formData.equipamento || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" required />
                    <input type="text" name="serial" placeholder="Número de Série *" value={formData.serial || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" required />
                    <input type="text" name="patrimonio" placeholder="Patrimônio" value={formData.patrimonio || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    
                    <input type="text" name="brand" placeholder="Marca" value={formData.brand || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <input type="text" name="model" placeholder="Modelo" value={formData.model || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <input type="text" name="tipo" placeholder="Tipo (ex: Notebook, Monitor)" value={formData.tipo || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />

                    <input type="text" name="usuarioAtual" placeholder="Usuário Atual" value={formData.usuarioAtual || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <input type="email" name="emailColaborador" placeholder="Email do Colaborador" value={formData.emailColaborador || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <input type="text" name="setor" placeholder="Setor" value={formData.setor || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    
                    <input type="text" name="local" placeholder="Localização" value={formData.local || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    
                    <div className="flex flex-col">
                         <label className="text-xs text-gray-500 dark:text-dark-text-secondary mb-1">Status</label>
                        <select name="status" value={formData.status || 'Estoque'} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary">
                            <option value="Estoque">Estoque</option>
                            <option value="Em Uso">Em Uso</option>
                            <option value="Manutenção">Manutenção</option>
                            <option value="Descartado">Descartado</option>
                        </select>
                    </div>

                    <div className="flex flex-col">
                         <label className="text-xs text-gray-500 dark:text-dark-text-secondary mb-1">Condição do Termo</label>
                         <select name="condicaoTermo" value={formData.condicaoTermo || 'N/A'} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary">
                            <option value="N/A">N/A</option>
                            <option value="Pendente">Pendente</option>
                            <option value="Assinado - Entrega">Assinado - Entrega</option>
                            <option value="Assinado - Devolução">Assinado - Devolução</option>
                        </select>
                    </div>

                    <div className="flex flex-col">
                         <label className="text-xs text-gray-500 dark:text-dark-text-secondary mb-1">Data Entrega</label>
                         <input type="date" name="dataEntregaUsuario" value={formData.dataEntregaUsuario || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    </div>
                    
                    <input type="text" name="notaCompra" placeholder="Nota Fiscal Compra" value={formData.notaCompra || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <input type="text" name="notaPlKm" placeholder="Nota PL/KM" value={formData.notaPlKm || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <input type="text" name="garantia" placeholder="Garantia" value={formData.garantia || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    
                     <div className="sm:col-span-3 lg:col-span-3">
                        <label className="text-xs text-gray-500 dark:text-dark-text-secondary mb-1">Observações</label>
                        <textarea name="observacoes" value={formData.observacoes || ''} onChange={handleChange} rows={3} className="w-full p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" placeholder="Observações adicionais..."></textarea>
                    </div>
                </div>
                <div className="p-6 border-t dark:border-dark-border bg-gray-50 dark:bg-dark-card/50 flex justify-end gap-3 flex-shrink-0">
                    <button type="button" onClick={onClose} className="px-4 py-2 bg-gray-300 dark:bg-gray-600 text-gray-800 dark:text-white rounded-md hover:bg-gray-400 dark:hover:bg-gray-500 transition-colors">Cancelar</button>
                    <button type="submit" disabled={isSaving} className="px-4 py-2 bg-brand-primary text-white rounded-md hover:bg-blue-600 transition-colors disabled:bg-gray-400">{isSaving ? 'Salvando...' : 'Salvar'}</button>
                </div>
            </form>
        </div>
    );
};

interface EquipmentListProps {
  currentUser: User;
  companyName: string;
}

const EquipmentList: React.FC<EquipmentListProps> = ({ currentUser, companyName }) => {
    const [equipment, setEquipment] = useState<Equipment[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [editingEquipment, setEditingEquipment] = useState<Equipment | null>(null);
    const [selectedTermo, setSelectedTermo] = useState<{equipment: Equipment, type: 'entrega' | 'devolucao'} | null>(null);
    
    const loadEquipment = async () => {
        setLoading(true);
        try {
            const data = await getEquipment(currentUser);
            setEquipment(data);
        } catch (error) {
            console.error("Failed to load equipment", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadEquipment();
    }, [currentUser]);

    const handleDelete = async (id: number) => {
        if (currentUser.role !== UserRole.Admin) return;
        if (window.confirm("Tem certeza que deseja excluir este equipamento?")) {
            try {
                await deleteEquipment(id, currentUser.username);
                loadEquipment();
            } catch (error) {
                console.error("Failed to delete equipment", error);
            }
        }
    };

    const handleEdit = (item: Equipment) => {
        setEditingEquipment(item);
        setIsModalOpen(true);
    };

    const handleAddNew = () => {
        setEditingEquipment(null);
        setIsModalOpen(true);
    };

    const handleCloseModal = () => {
        setIsModalOpen(false);
        setEditingEquipment(null);
    };

    const filteredEquipment = useMemo(() => {
        const lowerSearch = searchTerm.toLowerCase();
        return equipment.filter(item => 
            (item.equipamento?.toLowerCase().includes(lowerSearch)) ||
            (item.patrimonio?.toLowerCase().includes(lowerSearch)) ||
            (item.serial?.toLowerCase().includes(lowerSearch)) ||
            (item.usuarioAtual?.toLowerCase().includes(lowerSearch))
        );
    }, [equipment, searchTerm]);

    const handleExportToExcel = async () => {
        if (filteredEquipment.length === 0) {
            alert("Não há dados para exportar.");
            return;
        }

        try {
            await import('xlsx');
            const XLSX = (window as any).XLSX;
            
            if (!XLSX) {
                alert("Erro ao carregar a biblioteca de exportação.");
                return;
            }

            const dataToExport = filteredEquipment.map(item => ({
                'Equipamento': item.equipamento,
                'Marca': item.brand || '',
                'Modelo': item.model || '',
                'Patrimônio': item.patrimonio || '',
                'Serial': item.serial || '',
                'Usuário Atual': item.usuarioAtual || '',
                'Setor': item.setor || '',
                'Local': item.local || '',
                'Status': item.status || '',
                'Tipo': item.tipo || '',
                'Processador/Specs': item.identificador || '',
                'SO': item.nomeSO || '',
                'Memória': item.memoriaFisicaTotal || '',
                'Nota Fiscal': item.notaCompra || '',
                'Data Entrega': item.dataEntregaUsuario ? new Date(item.dataEntregaUsuario).toLocaleDateString('pt-BR') : '',
                'Termo': item.condicaoTermo || 'N/A',
                'Observações': item.observacoes || ''
            }));

            const ws = XLSX.utils.json_to_sheet(dataToExport);
            const wb = XLSX.utils.book_new();
            XLSX.utils.book_append_sheet(wb, ws, "Inventário");
            
            XLSX.writeFile(wb, `inventario_equipamentos_${new Date().toISOString().split('T')[0]}.xlsx`);

        } catch (error) {
            console.error("Erro ao exportar:", error);
            alert("Erro ao gerar arquivo Excel.");
        }
    };

    return (
        <div className="bg-white dark:bg-dark-card p-4 sm:p-6 rounded-lg shadow-md">
            <div className="flex flex-col sm:flex-row justify-between sm:items-center mb-4 gap-4">
                <h2 className="text-2xl font-bold text-brand-dark dark:text-dark-text-primary">Inventário de Equipamentos</h2>
                <div className="flex flex-wrap gap-2">
                    <button onClick={handleExportToExcel} className="bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 flex items-center gap-2">
                        <Icon name="FileDown" size={18}/> Exportar Excel
                    </button>
                    <button onClick={handleAddNew} className="bg-brand-primary text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2">
                        <Icon name="Plus" size={18}/> Novo Item
                    </button>
                </div>
            </div>

            <div className="mb-4">
                <input 
                    type="text" 
                    placeholder="Buscar por nome, patrimônio, serial ou usuário..." 
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-800 dark:text-dark-text-primary"
                />
            </div>

            {loading ? (
                <div className="flex justify-center items-center py-10">
                    <Icon name="LoaderCircle" className="animate-spin text-brand-primary" size={48} />
                </div>
            ) : (
                <div className="overflow-x-auto">
                    <table className="w-full text-sm text-left text-gray-700 dark:text-dark-text-secondary">
                        <thead className="text-xs text-gray-800 dark:text-dark-text-primary uppercase bg-gray-100 dark:bg-gray-900/50">
                            <tr>
                                <th className="px-6 py-3">Equipamento</th>
                                <th className="px-6 py-3">Patrimônio</th>
                                <th className="px-6 py-3">Serial</th>
                                <th className="px-6 py-3">Usuário</th>
                                <th className="px-6 py-3">Setor</th>
                                <th className="px-6 py-3">Status</th>
                                <th className="px-6 py-3 text-right">Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredEquipment.map(item => (
                                <tr key={item.id} className="bg-white dark:bg-dark-card border-b dark:border-dark-border hover:bg-gray-50 dark:hover:bg-gray-700">
                                    <td className="px-6 py-4 font-medium text-gray-900 dark:text-dark-text-primary">{item.equipamento}</td>
                                    <td className="px-6 py-4">{item.patrimonio}</td>
                                    <td className="px-6 py-4 font-mono text-xs">{item.serial}</td>
                                    <td className="px-6 py-4">{item.usuarioAtual}</td>
                                    <td className="px-6 py-4">{item.setor}</td>
                                    <td className="px-6 py-4">
                                        <span className={`px-2 py-1 rounded-full text-xs font-semibold ${
                                            item.status === 'Em Uso' ? 'bg-green-100 text-green-800' :
                                            item.status === 'Estoque' ? 'bg-yellow-100 text-yellow-800' :
                                            item.status === 'Manutenção' ? 'bg-orange-100 text-orange-800' :
                                            'bg-gray-100 text-gray-800'
                                        }`}>
                                            {item.status}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 text-right flex justify-end gap-2">
                                        <div className="relative group">
                                            <button className="text-gray-500 hover:text-brand-primary dark:text-gray-400 dark:hover:text-white">
                                                <Icon name="FileText" size={18} />
                                            </button>
                                            <div className="absolute right-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-md shadow-lg py-1 z-10 hidden group-hover:block border dark:border-dark-border">
                                                <button 
                                                    onClick={() => setSelectedTermo({equipment: item, type: 'entrega'})}
                                                    className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                                                >
                                                    Termo de Entrega
                                                </button>
                                                <button 
                                                    onClick={() => setSelectedTermo({equipment: item, type: 'devolucao'})}
                                                    className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                                                >
                                                    Termo de Devolução
                                                </button>
                                            </div>
                                        </div>
                                        <button onClick={() => handleEdit(item)} className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300" title="Editar">
                                            <Icon name="Pencil" size={18} />
                                        </button>
                                        {currentUser.role === UserRole.Admin && (
                                            <button onClick={() => handleDelete(item.id)} className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300" title="Excluir">
                                                <Icon name="Trash2" size={18} />
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            ))}
                             {filteredEquipment.length === 0 && (
                                <tr>
                                    <td colSpan={7} className="px-6 py-10 text-center text-gray-500 dark:text-dark-text-secondary">
                                        <Icon name="SearchX" size={48} className="mx-auto mb-2 opacity-50" />
                                        Nenhum equipamento encontrado.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            )}

            {isModalOpen && (
                <EquipmentFormModal 
                    equipment={editingEquipment} 
                    onClose={handleCloseModal} 
                    onSave={loadEquipment} 
                    currentUser={currentUser}
                />
            )}

            {selectedTermo && (
                <TermoResponsabilidade
                    equipment={selectedTermo.equipment}
                    user={currentUser}
                    onClose={() => setSelectedTermo(null)}
                    companyName={companyName}
                    termoType={selectedTermo.type}
                />
            )}
        </div>
    );
};

export default EquipmentList;
