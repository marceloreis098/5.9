
import React, { useState, useEffect, useMemo } from 'react';
import { License, User, UserRole } from '../types';
import { getLicenses, addLicense, updateLicense, deleteLicense, getLicenseTotals, saveLicenseTotals, renameProduct } from '../services/apiService';
import Icon from './common/Icon';

interface LicenseFormModalProps {
    license: License | null;
    onClose: () => void;
    onSave: () => void;
    currentUser: User;
    productNames: string[];
}

const LicenseFormModal: React.FC<LicenseFormModalProps> = ({ license, onClose, onSave, currentUser, productNames }) => {
    const [formData, setFormData] = useState<Partial<License>>({
        produto: '',
        tipoLicenca: '',
        chaveSerial: '',
        dataExpiracao: '',
        usuario: '',
        cargo: '',
        setor: '',
        gestor: '',
        centroCusto: '',
        contaRazao: '',
        nomeComputador: '',
        numeroChamado: '',
        observacoes: '',
        empresa: ''
    });
    const [isSaving, setIsSaving] = useState(false);

    useEffect(() => {
        if (license) {
            setFormData({
                ...license,
                dataExpiracao: license.dataExpiracao ? license.dataExpiracao.split('T')[0] : ''
            });
        }
    }, [license]);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSaving(true);
        try {
            if (license) {
                await updateLicense({ ...formData, id: license.id } as License, currentUser.username);
            } else {
                await addLicense(formData as any, currentUser);
                if (currentUser.role !== UserRole.Admin) {
                    alert("Licença adicionada. Aguardando aprovação do administrador.");
                }
            }
            onSave();
            onClose();
        } catch (error) {
            console.error("Failed to save license", error);
            alert("Erro ao salvar licença.");
        } finally {
            setIsSaving(false);
        }
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center z-50 p-4">
            <form onSubmit={handleSubmit} className="bg-white dark:bg-dark-card rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] flex flex-col">
                <div className="p-6 border-b dark:border-dark-border">
                    <h3 className="text-xl font-bold text-brand-dark dark:text-dark-text-primary">{license ? 'Editar Licença' : 'Nova Licença'}</h3>
                </div>
                <div className="p-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 overflow-y-auto">
                     <div className="sm:col-span-1">
                        <label className="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Produto</label>
                        <input 
                            type="text" 
                            name="produto" 
                            list="product-suggestions" 
                            placeholder="Ex: Windows 11 Pro" 
                            value={formData.produto || ''} 
                            onChange={handleChange} 
                            className="w-full p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" 
                            required 
                        />
                        <datalist id="product-suggestions">
                            {productNames.map(name => <option key={name} value={name} />)}
                        </datalist>
                    </div>
                    <input type="text" name="chaveSerial" placeholder="Chave Serial *" value={formData.chaveSerial || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" required />
                    <input type="text" name="usuario" placeholder="Usuário *" value={formData.usuario || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" required />
                    
                    <input type="text" name="tipoLicenca" placeholder="Tipo (Ex: Perpétua, Assinatura)" value={formData.tipoLicenca || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <div className="flex flex-col">
                        <label className="text-xs text-gray-500 dark:text-dark-text-secondary">Data Expiração</label>
                        <input type="date" name="dataExpiracao" value={formData.dataExpiracao || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    </div>
                     <input type="text" name="empresa" placeholder="Empresa" value={formData.empresa || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    
                    <input type="text" name="setor" placeholder="Setor" value={formData.setor || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <input type="text" name="cargo" placeholder="Cargo" value={formData.cargo || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <input type="text" name="gestor" placeholder="Gestor" value={formData.gestor || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    
                    <input type="text" name="centroCusto" placeholder="Centro de Custo" value={formData.centroCusto || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <input type="text" name="contaRazao" placeholder="Conta Razão" value={formData.contaRazao || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                    <input type="text" name="nomeComputador" placeholder="Nome do Computador (Hostname)" value={formData.nomeComputador || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />
                     <input type="text" name="numeroChamado" placeholder="Número do Chamado" value={formData.numeroChamado || ''} onChange={handleChange} className="p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" />

                     <div className="sm:col-span-2 lg:col-span-3">
                        <label className="text-xs text-gray-500 dark:text-dark-text-secondary mb-1">Observações</label>
                        <textarea name="observacoes" value={formData.observacoes || ''} onChange={handleChange} rows={2} className="w-full p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-dark-text-primary" placeholder="Observações adicionais..."></textarea>
                    </div>
                </div>
                <div className="p-6 border-t dark:border-dark-border bg-gray-50 dark:bg-dark-card/50 flex justify-end gap-3">
                    <button type="button" onClick={onClose} className="px-4 py-2 bg-gray-300 dark:bg-gray-600 text-gray-800 dark:text-white rounded-md hover:bg-gray-400 dark:hover:bg-gray-500">Cancelar</button>
                    <button type="submit" disabled={isSaving} className="px-4 py-2 bg-brand-primary text-white rounded-md hover:bg-blue-600 disabled:bg-gray-400">{isSaving ? 'Salvando...' : 'Salvar'}</button>
                </div>
            </form>
        </div>
    );
};

const ProductManagerModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    productNames: string[];
    totalLicenses: Record<string, number>;
    onSave: (newProductNames: string[], renames: Record<string, string>, newTotals: Record<string, number>) => void;
}> = ({ isOpen, onClose, productNames, totalLicenses, onSave }) => {
    // Use objects with IDs to track items stably, avoiding index shift issues
    const [products, setProducts] = useState<{ id: string, currentName: string, originalName: string | null }[]>([]);
    const [editedTotals, setEditedTotals] = useState<Record<string, number>>({});
    const [newProductName, setNewProductName] = useState('');

    useEffect(() => {
        if (isOpen) {
            // Initialize state from props
            const initialProducts = productNames.map((name, idx) => ({
                id: `existing-${idx}`,
                currentName: name,
                originalName: name
            }));
            setProducts(initialProducts);
            setEditedTotals({...totalLicenses});
            setNewProductName('');
        }
    }, [isOpen, productNames, totalLicenses]);

    if (!isOpen) return null;

    const handleNameChange = (id: string, newName: string) => {
        setProducts(prev => prev.map(p => {
            if (p.id === id) {
                // Handle totals update: move value from old name to new name
                const oldName = p.currentName;
                if (oldName !== newName) {
                    setEditedTotals(prevTotals => {
                        const val = prevTotals[oldName] || 0;
                        const newTots = { ...prevTotals };
                        delete newTots[oldName];
                        newTots[newName] = val;
                        return newTots;
                    });
                }
                return { ...p, currentName: newName };
            }
            return p;
        }));
    };

    const handleTotalChange = (productName: string, newTotal: string) => {
        const num = parseInt(newTotal);
        setEditedTotals(prev => ({
            ...prev,
            [productName]: isNaN(num) ? 0 : num
        }));
    };

    const handleAddProduct = () => {
        const trimmedName = newProductName.trim();
        if (!trimmedName) return;

        if (products.some(p => p.currentName.toLowerCase() === trimmedName.toLowerCase())) {
            alert("Este produto já existe na lista.");
            return;
        }

        const newProduct = {
            id: `new-${Date.now()}`,
            currentName: trimmedName,
            originalName: null // It's new, so no original name in DB
        };

        setProducts(prev => [newProduct, ...prev]);
        setEditedTotals(prev => ({ ...prev, [trimmedName]: 0 }));
        setNewProductName('');
    };

    const handleDeleteProduct = (id: string) => {
        const productToDelete = products.find(p => p.id === id);
        
        // Important: Remove from editedTotals to ensure it's removed from DB on save
        if (productToDelete) {
            setEditedTotals(prev => {
                const next = { ...prev };
                delete next[productToDelete.currentName];
                return next;
            });
        }

        setProducts(prev => prev.filter(p => p.id !== id));
    };

    const handleSaveClick = () => {
        const newProductNames = products.map(p => p.currentName).filter(n => n.trim() !== '');
        const renames: Record<string, string> = {};

        products.forEach(p => {
            if (p.originalName && p.currentName !== p.originalName && p.currentName.trim() !== '') {
                renames[p.originalName] = p.currentName;
            }
        });

        onSave(newProductNames, renames, editedTotals);
        onClose();
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center z-50 p-4">
            <div className="bg-white dark:bg-dark-card rounded-lg shadow-xl w-full max-w-lg max-h-[80vh] flex flex-col">
                <div className="p-6 border-b dark:border-dark-border">
                    <h3 className="text-xl font-bold text-brand-dark dark:text-dark-text-primary">Gerenciar Produtos e Totais</h3>
                    <p className="text-sm text-gray-500 dark:text-dark-text-secondary">Crie, renomeie produtos ou defina o total de licenças compradas.</p>
                </div>
                
                <div className="p-4 border-b dark:border-dark-border bg-gray-50 dark:bg-dark-bg/30">
                    <div className="flex gap-2">
                        <input 
                            type="text" 
                            value={newProductName}
                            onChange={(e) => setNewProductName(e.target.value)}
                            placeholder="Nome do novo produto" 
                            className="flex-grow p-2 border dark:border-dark-border rounded bg-white dark:bg-gray-800 dark:text-white text-sm"
                        />
                        <button 
                            onClick={handleAddProduct}
                            className="bg-green-600 text-white px-3 py-2 rounded hover:bg-green-700 flex items-center gap-1 transition-colors"
                            title="Adicionar Produto"
                        >
                            <Icon name="Plus" size={16} />
                            <span className="text-sm font-medium">Adicionar</span>
                        </button>
                    </div>
                </div>

                <div className="p-6 overflow-y-auto space-y-4">
                    {products.map((product) => (
                        <div key={product.id} className="flex items-center gap-2 p-2 border-b dark:border-dark-border last:border-0">
                            <div className="flex-grow">
                                <label className="block text-xs text-gray-500 mb-1">Nome do Produto</label>
                                <input
                                    type="text"
                                    value={product.currentName}
                                    onChange={(e) => handleNameChange(product.id, e.target.value)}
                                    className="w-full p-2 border dark:border-dark-border rounded bg-gray-50 dark:bg-gray-700 dark:text-white text-sm"
                                />
                            </div>
                            <div className="w-24">
                                <label className="block text-xs text-gray-500 mb-1">Total Adq.</label>
                                <input
                                    type="number"
                                    value={editedTotals[product.currentName] || 0}
                                    onChange={(e) => handleTotalChange(product.currentName, e.target.value)}
                                    className="w-full p-2 border dark:border-dark-border rounded bg-white dark:bg-gray-800 text-center text-sm"
                                    min="0"
                                />
                            </div>
                             <div className="flex items-end pb-1">
                                <button
                                    onClick={() => handleDeleteProduct(product.id)}
                                    className="text-red-500 hover:text-red-700 p-2 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                                    title="Remover Produto"
                                >
                                    <Icon name="Trash2" size={18} />
                                </button>
                            </div>
                        </div>
                    ))}
                     {products.length === 0 && <p className="text-center text-gray-500">Nenhum produto cadastrado.</p>}
                </div>
                <div className="p-6 border-t dark:border-dark-border bg-gray-50 dark:bg-dark-card/50 flex justify-end gap-3">
                    <button onClick={onClose} className="px-4 py-2 bg-gray-300 dark:bg-gray-600 text-gray-800 dark:text-white rounded-md hover:bg-gray-400">Cancelar</button>
                    <button onClick={handleSaveClick} className="px-4 py-2 bg-brand-primary text-white rounded-md hover:bg-blue-600">Salvar Alterações</button>
                </div>
            </div>
        </div>
    );
};

interface LicenseControlProps {
    currentUser: User;
}

const LicenseControl: React.FC<LicenseControlProps> = ({ currentUser }) => {
    const [licenses, setLicenses] = useState<License[]>([]);
    const [totalLicenses, setTotalLicenses] = useState<Record<string, number>>({});
    const [productNames, setProductNames] = useState<string[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [isManagerOpen, setIsManagerOpen] = useState(false);
    const [editingLicense, setEditingLicense] = useState<License | null>(null);
    
    // State for accordion
    const [expandedProducts, setExpandedProducts] = useState<Record<string, boolean>>({});

    const loadLicensesAndProducts = async () => {
        setLoading(true);
        try {
            const [licensesData, totalsData] = await Promise.all([
                getLicenses(currentUser),
                getLicenseTotals()
            ]);
            setLicenses(licensesData);
            setTotalLicenses(totalsData || {});

            // Define product names strictly from the managed 'totalsData' to avoid pollution from legacy license names
            // If totalsData is empty, the list will be empty, forcing users to use the manager
            const managedNames = Object.keys(totalsData || {}).sort();
            setProductNames(managedNames);

        } catch (error) {
            console.error("Failed to load data", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadLicensesAndProducts();
    }, [currentUser]);

    const handleDelete = async (id: number) => {
        if (currentUser.role !== UserRole.Admin) return;
        if (window.confirm("Tem certeza que deseja excluir esta licença?")) {
            try {
                await deleteLicense(id, currentUser.username);
                loadLicensesAndProducts();
            } catch (error) {
                console.error("Failed to delete license", error);
            }
        }
    };

    const handleEdit = (item: License) => {
        setEditingLicense(item);
        setIsModalOpen(true);
    };

    const handleAddNew = () => {
        setEditingLicense(null);
        setIsModalOpen(true);
    };
    
    const toggleProduct = (productName: string) => {
        setExpandedProducts(prev => ({
            ...prev,
            [productName]: !prev[productName]
        }));
    };

     const handleManagerSave = async (newProductNames: string[], renames: Record<string, string>, newTotals: Record<string, number>) => {
        try {
             // 1. Validate if deletions are valid (no licenses using deleted name)
            const originalProductNames = new Set<string>(productNames);
            const currentProductNames = new Set<string>(newProductNames);
            const deletedProductNames: string[] = [];
            originalProductNames.forEach(name => {
                // Check if name is missing AND not being renamed (if renamed, it's safe)
                if (!currentProductNames.has(name) && !renames[name]) {
                    deletedProductNames.push(name);
                }
            });
    
            const errors: string[] = [];
            deletedProductNames.forEach(name => {
                if (licenses.some(l => l.produto === name)) {
                    errors.push(`- "${name}" não pode ser removido pois ainda existem licenças associadas a ele.`);
                }
            });
    
            if (errors.length > 0) {
                alert(`Não foi possível salvar as alterações:\n${errors.join('\n')}`);
                return;
            }

            // 2. Apply renames to database
            const renamePromises = Object.entries(renames).map(([oldName, newName]) => {
                if (oldName !== newName && productNames.includes(oldName)) {
                    return renameProduct(oldName, newName, currentUser.username);
                }
                return Promise.resolve();
            });
            
            if (renamePromises.length > 0) {
                await Promise.all(renamePromises);
            }

            // 3. Save totals
            await saveLicenseTotals(newTotals, currentUser.username);

            alert("Produtos atualizados com sucesso!");
            loadLicensesAndProducts();

        } catch (error) {
            console.error("Failed to save product changes", error);
            alert("Erro ao salvar alterações de produtos.");
        }
    };


    const filteredLicenses = useMemo(() => {
        const lowerSearch = searchTerm.toLowerCase();
        return licenses.filter(item =>
            item.produto.toLowerCase().includes(lowerSearch) ||
            item.usuario.toLowerCase().includes(lowerSearch) ||
            item.chaveSerial.toLowerCase().includes(lowerSearch)
        );
    }, [licenses, searchTerm]);
    
    // Group licenses by product
    const groupedLicenses = useMemo(() => {
        const groups: Record<string, License[]> = {};
        productNames.forEach(name => groups[name] = []); // Initialize empty arrays for all managed products

        filteredLicenses.forEach(l => {
            // Ensure the product bucket exists even if product isn't in productNames (legacy support for display)
            if (!groups[l.produto]) groups[l.produto] = [];
            groups[l.produto].push(l);
        });
        return groups;
    }, [filteredLicenses, productNames]);

    // Get all unique product keys for rendering (Managed + Legacy present in filtered results)
    const displayProductKeys = useMemo(() => {
        return Object.keys(groupedLicenses).sort();
    }, [groupedLicenses]);


    const handleExportProductToExcel = async (productName: string, licensesToExport: License[]) => {
        if (licensesToExport.length === 0) {
            alert("Não há licenças para exportar neste produto.");
            return;
        }

        try {
            await import('xlsx');
            const XLSX = (window as any).XLSX;
            
            if (!XLSX) {
                alert("Erro ao carregar a biblioteca de exportação.");
                return;
            }

            const dataToExport = licensesToExport.map(item => ({
                'Produto': item.produto,
                'Chave Serial': item.chaveSerial,
                'Tipo': item.tipoLicenca || '',
                'Usuário': item.usuario,
                'Email/Gestor': item.gestor || '',
                'Setor': item.setor || '',
                'Cargo': item.cargo || '',
                'Empresa': item.empresa || '',
                'Validade': item.dataExpiracao ? new Date(item.dataExpiracao).toLocaleDateString('pt-BR') : 'N/A',
                'Hostname': item.nomeComputador || '',
                'Centro Custo': item.centroCusto || '',
                'Observações': item.observacoes || ''
            }));

            const ws = XLSX.utils.json_to_sheet(dataToExport);
            const wb = XLSX.utils.book_new();
            // Sanitizar nome do produto para nome de arquivo
            const safeName = productName.replace(/[^a-z0-9]/gi, '_').toLowerCase();
            XLSX.utils.book_append_sheet(wb, ws, "Licenças");
            
            XLSX.writeFile(wb, `licencas_${safeName}_${new Date().toISOString().split('T')[0]}.xlsx`);

        } catch (error) {
            console.error("Erro ao exportar:", error);
            alert("Erro ao gerar arquivo Excel.");
        }
    };

    return (
        <div className="space-y-6">
             {/* Header Actions */}
             <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4 bg-white dark:bg-dark-card p-4 rounded-lg shadow-md">
                <h2 className="text-2xl font-bold text-brand-dark dark:text-dark-text-primary">Controle de Licenças</h2>
                <div className="flex flex-wrap gap-2">
                    {currentUser.role === UserRole.Admin && (
                         <button onClick={() => setIsManagerOpen(true)} className="bg-brand-secondary text-white px-4 py-2 rounded-lg hover:bg-gray-700 flex items-center gap-2">
                            <Icon name="Settings" size={18}/> Gerenciar Produtos
                        </button>
                    )}
                    <button onClick={handleAddNew} className="bg-brand-primary text-white px-4 py-2 rounded-lg hover:bg-blue-700 flex items-center gap-2">
                        <Icon name="Plus" size={18}/> Nova Licença
                    </button>
                </div>
            </div>

            <div className="mb-4">
                <input
                    type="text"
                    placeholder="Buscar por produto, usuário ou chave..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full p-3 border dark:border-dark-border rounded-lg bg-white dark:bg-dark-card text-gray-800 dark:text-dark-text-primary shadow-sm focus:ring-2 focus:ring-brand-primary focus:border-transparent"
                />
            </div>

            {loading ? (
                <div className="flex justify-center items-center py-10">
                    <Icon name="LoaderCircle" className="animate-spin text-brand-primary" size={48} />
                </div>
            ) : (
                <div className="grid grid-cols-1 gap-4">
                    {displayProductKeys.map(productName => {
                        const productLicenses = groupedLicenses[productName] || [];
                        
                        // If filtering, hide empty products
                        if (searchTerm && productLicenses.length === 0) return null;
                        
                        const inUseCount = productLicenses.length;
                        // Only managed products have totals
                        const isManaged = productNames.includes(productName);
                        const totalCount = totalLicenses[productName] || 0;
                        const availableCount = totalCount - inUseCount;
                        const isExpanded = expandedProducts[productName];

                        return (
                            <div key={productName} className="bg-white dark:bg-dark-card rounded-lg shadow-md overflow-hidden border dark:border-dark-border">
                                {/* Accordion Header */}
                                <div 
                                    className="p-4 flex flex-col sm:flex-row justify-between items-center gap-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                                    onClick={() => toggleProduct(productName)}
                                >
                                    <div className="flex-grow">
                                        <div className="flex items-center gap-2">
                                            <Icon name={isExpanded ? "ChevronUp" : "ChevronDown"} size={20} className="text-gray-500" />
                                            <h3 className="text-lg font-bold text-brand-primary dark:text-white flex items-center gap-2">
                                                {productName}
                                                {!isManaged && <span className="text-xs bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300 px-1.5 py-0.5 rounded">Não Gerenciado</span>}
                                            </h3>
                                        </div>
                                        <div className="mt-2 flex gap-4 text-sm">
                                            <span className="text-gray-600 dark:text-dark-text-secondary">Em uso: <strong className="text-gray-900 dark:text-white">{inUseCount}</strong></span>
                                            {isManaged && (
                                                <>
                                                    <span className="text-gray-600 dark:text-dark-text-secondary">Total: <strong className="text-gray-900 dark:text-white">{totalCount}</strong></span>
                                                    <span className={`font-semibold ${availableCount < 0 ? 'text-red-500' : availableCount === 0 ? 'text-orange-500' : 'text-green-500'}`}>
                                                        {availableCount} Disponíveis
                                                    </span>
                                                </>
                                            )}
                                        </div>
                                        {isManaged && (
                                            <div className="w-full sm:w-64 bg-gray-200 rounded-full h-1.5 mt-2 dark:bg-gray-700">
                                                <div className={`h-1.5 rounded-full ${availableCount < 0 ? 'bg-red-500' : 'bg-blue-500'}`} style={{ width: `${Math.min((inUseCount / (totalCount || 1)) * 100, 100)}%` }}></div>
                                            </div>
                                        )}
                                    </div>
                                    
                                    <div className="flex items-center gap-3" onClick={(e) => e.stopPropagation()}>
                                        <button 
                                            onClick={() => handleExportProductToExcel(productName, productLicenses)}
                                            className="bg-green-600 text-white px-3 py-2 rounded hover:bg-green-700 flex items-center gap-2 text-sm transition-colors"
                                            title={`Exportar licenças de ${productName}`}
                                        >
                                            <Icon name="FileDown" size={16}/> Exportar Excel
                                        </button>
                                    </div>
                                </div>

                                {/* Accordion Body */}
                                {isExpanded && (
                                    <div className="border-t dark:border-dark-border p-4 bg-gray-50 dark:bg-dark-bg/30">
                                        {productLicenses.length > 0 ? (
                                            <div className="overflow-x-auto">
                                                <table className="w-full text-sm text-left text-gray-700 dark:text-dark-text-secondary">
                                                    <thead className="text-xs text-gray-800 dark:text-dark-text-primary uppercase bg-gray-200 dark:bg-gray-800">
                                                        <tr>
                                                            <th className="px-4 py-3">Chave Serial</th>
                                                            <th className="px-4 py-3">Usuário</th>
                                                            <th className="px-4 py-3">Validade</th>
                                                            <th className="px-4 py-3 text-right">Ações</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {productLicenses.map(item => {
                                                            const isExpired = item.dataExpiracao && item.dataExpiracao !== 'N/A' && new Date(item.dataExpiracao) < new Date();
                                                            return (
                                                                <tr key={item.id} className="bg-white dark:bg-dark-card border-b dark:border-dark-border hover:bg-gray-100 dark:hover:bg-gray-700">
                                                                    <td className="px-4 py-3 font-mono text-xs">{item.chaveSerial}</td>
                                                                    <td className="px-4 py-3">{item.usuario}</td>
                                                                    <td className="px-4 py-3">
                                                                        {item.dataExpiracao ? (
                                                                            <span className={`${isExpired ? 'text-red-500 font-bold' : ''}`}>
                                                                                {new Date(item.dataExpiracao).toLocaleDateString('pt-BR')}
                                                                                {isExpired && <span className="ml-1 text-xs bg-red-100 text-red-800 px-1 rounded">Exp</span>}
                                                                            </span>
                                                                        ) : 'N/A'}
                                                                    </td>
                                                                    <td className="px-4 py-3 text-right flex justify-end gap-2">
                                                                        <button onClick={() => handleEdit(item)} className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300" title="Editar">
                                                                            <Icon name="Pencil" size={16} />
                                                                        </button>
                                                                        {currentUser.role === UserRole.Admin && (
                                                                            <button onClick={() => handleDelete(item.id)} className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300" title="Excluir">
                                                                                <Icon name="Trash2" size={16} />
                                                                            </button>
                                                                        )}
                                                                    </td>
                                                                </tr>
                                                            );
                                                        })}
                                                    </tbody>
                                                </table>
                                            </div>
                                        ) : (
                                            <div className="text-center py-4 text-gray-500 dark:text-dark-text-secondary">
                                                Nenhuma licença cadastrada para este produto.
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                    
                    {displayProductKeys.length === 0 && !searchTerm && (
                        <div className="text-center py-10 text-gray-500 dark:text-dark-text-secondary">
                            <Icon name="SearchX" size={48} className="mx-auto mb-2 opacity-50" />
                            Nenhum produto cadastrado. Adicione uma nova licença ou gerencie produtos.
                        </div>
                    )}
                    
                    {filteredLicenses.length === 0 && searchTerm && (
                        <div className="text-center py-10 text-gray-500 dark:text-dark-text-secondary">
                             <Icon name="SearchX" size={48} className="mx-auto mb-2 opacity-50" />
                            Nenhum resultado encontrado para a busca.
                        </div>
                    )}
                </div>
            )}

            {isModalOpen && (
                <LicenseFormModal
                    license={editingLicense}
                    onClose={() => setIsModalOpen(false)}
                    onSave={loadLicensesAndProducts}
                    currentUser={currentUser}
                    productNames={productNames}
                />
            )}

            {isManagerOpen && (
                <ProductManagerModal
                    isOpen={isManagerOpen}
                    onClose={() => setIsManagerOpen(false)}
                    productNames={productNames}
                    totalLicenses={totalLicenses}
                    onSave={handleManagerSave}
                />
            )}
        </div>
    );
};

export default LicenseControl;
