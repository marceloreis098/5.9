
import React, { useState, useRef } from 'react';
import { User, License } from '../types';
import Icon from './common/Icon';
import { importLicenses } from '../services/apiService';

// Add new type for the import payload
interface LicenseImportData {
    productName: string;
    licenses: Omit<License, 'id' | 'produto' | 'approval_status' | 'rejection_reason'>[];
}

interface LicenseImportProps {
    currentUser: User;
    productNames: string[];
    onImportSuccess: () => void;
}

const LicenseImport: React.FC<LicenseImportProps> = ({ currentUser, productNames, onImportSuccess }) => {
    const [selectedProduct, setSelectedProduct] = useState<string>('');
    const [csvFile, setCsvFile] = useState<File | null>(null);
    const [isSaving, setIsSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);

    const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (file) {
            setCsvFile(file);
            setError(null);
        }
    };

    const parseCsv = (fileText: string): Omit<License, 'id' | 'produto' | 'approval_status' | 'rejection_reason'>[] => {
        const lines = fileText.trim().split(/\r\n|\n/);
        if (lines.length < 2) {
            throw new Error("O arquivo CSV deve conter um cabeçalho e pelo menos uma linha de dados.");
        }

        const headerLine = lines[0].replace(/^\uFEFF/, ''); // Robust BOM removal
        const header = headerLine.split(';').map(h => h.trim().toLowerCase());
        const rows = lines.slice(1);

        const expectedHeaders = ['produto', 'tipolicenca', 'chaveserial', 'dataexpiracao', 'usuario', 'cargo', 'setor', 'gestor', 'centrocusto', 'contarazao', 'nomecomputador', 'numerochamado'];
        
        if (!expectedHeaders.some(h => header.includes(h))) {
            throw new Error(`Cabeçalho do CSV inválido. Certifique-se que o delimitador é ponto e vírgula (;) e que as colunas esperadas estão presentes.`);
        }

        return rows.map((row, rowIndex) => {
            if (!row.trim()) return null;

            const values = row.split(';');
            const entry: any = {};
            header.forEach((colName, index) => {
                const keyMap: { [key: string]: keyof License } = {
                    'produto': 'produto', 'tipolicenca': 'tipoLicenca', 'chaveserial': 'chaveSerial',
                    'dataexpiracao': 'dataExpiracao', 'usuario': 'usuario', 'cargo': 'cargo',
                    'setor': 'setor', 'gestor': 'gestor', 'centrocusto': 'centroCusto',
                    'contarazao': 'contaRazao', 'nomecomputador': 'nomeComputador', 'numerochamado': 'numeroChamado'
                };
                const key = keyMap[colName.replace(/\s+/g, '')];
                if (key && index < values.length) {
                    entry[key] = values[index]?.trim() || '';
                }
            });
            
            if (typeof entry.produto === 'undefined') {
                 throw new Error(`A coluna 'produto' é obrigatória no arquivo CSV, mas não foi encontrada ou mapeada corretamente. Verifique o cabeçalho do arquivo.`);
            }

            if (entry.produto.toLowerCase() !== selectedProduct.toLowerCase()) {
                throw new Error(`Erro na linha ${rowIndex + 2}: o produto "${entry.produto}" no arquivo não corresponde ao produto selecionado "${selectedProduct}".`);
            }
            if (!entry.chaveSerial || !entry.usuario) {
                throw new Error(`Erro na linha ${rowIndex + 2}: 'chaveSerial' e 'usuario' são campos obrigatórios.`);
            }

            delete entry.produto;
            return entry;
        }).filter((item): item is Omit<License, 'id' | 'produto' | 'approval_status' | 'rejection_reason'> => item !== null);
    };

    const handleImport = async () => {
        if (!selectedProduct || !csvFile) {
            setError("Por favor, selecione um produto e um arquivo CSV.");
            return;
        }
        if (!window.confirm(`ATENÇÃO: Esta ação substituirá TODAS as licenças existentes para o produto "${selectedProduct}". Deseja continuar?`)) return;

        setIsSaving(true);
        setError(null);

        try {
            const fileText = await csvFile.text();
            const licenses = parseCsv(fileText);

            const importData: LicenseImportData = {
                productName: selectedProduct,
                licenses: licenses
            };
            
            const result = await importLicenses(importData, currentUser.username);

            if (result.success) {
                alert(result.message);
                onImportSuccess();
                setSelectedProduct('');
                setCsvFile(null);
                if (fileInputRef.current) fileInputRef.current.value = '';
            } else {
                setError(result.message);
            }
        } catch (e: any) {
            setError(`Falha ao importar: ${e.message}`);
        } finally {
            setIsSaving(false);
        }
    };

    return (
        <div className="p-6 bg-gray-50 dark:bg-dark-bg rounded-lg border dark:border-dark-border mt-8">
            <h3 className="text-lg font-bold text-brand-secondary dark:text-dark-text-primary mb-2 flex items-center gap-2">
                <Icon name="FileUp" size={20} />
                Importar Licenças via CSV
            </h3>
            <p className="text-sm text-gray-600 dark:text-dark-text-secondary mb-4">
                Esta ferramenta permite substituir todas as licenças de um produto específico com os dados de um arquivo CSV.
            </p>

            {error && <div className="mb-4 bg-red-100 border-l-4 border-red-500 text-red-700 p-4" role="alert"><p>{error}</p></div>}
            
            <div className="space-y-4 max-w-lg">
                <div>
                    <label htmlFor="productSelect" className="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Selecione um produto para importar</label>
                    <select
                        id="productSelect"
                        value={selectedProduct}
                        onChange={(e) => setSelectedProduct(e.target.value)}
                        disabled={isSaving}
                        className="w-full p-2 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800 text-gray-800 dark:text-dark-text-primary focus:ring-brand-primary focus:border-brand-primary"
                    >
                        <option value="" disabled>Selecione um produto</option>
                        {productNames.map(name => <option key={name} value={name}>{name}</option>)}
                    </select>
                </div>
                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Selecione o arquivo CSV</label>
                     <div className="bg-white dark:bg-dark-card p-4 rounded-lg shadow-inner">
                        <input
                            type="file"
                            ref={fileInputRef}
                            onChange={handleFileChange}
                            accept=".csv"
                            disabled={isSaving || !selectedProduct}
                            className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-gray-200 dark:file:bg-gray-700 file:text-gray-700 dark:file:text-gray-200 hover:file:bg-gray-300 dark:hover:file:bg-gray-600 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                        />
                    </div>
                </div>
                <div className="pt-2">
                    <button
                        onClick={handleImport}
                        disabled={isSaving || !selectedProduct || !csvFile}
                        className="w-full bg-brand-secondary hover:bg-brand-dark text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline transition-colors disabled:bg-gray-400 flex items-center justify-center gap-2"
                    >
                        {isSaving ? <Icon name="LoaderCircle" className="animate-spin" /> : <Icon name="CloudUpload" />}
                        {isSaving ? 'Importando...' : 'Importar Licenças (CSV)'}
                    </button>
                    <p className="text-xs text-center mt-2 text-gray-500 dark:text-dark-text-secondary">Isto substituirá todas as licenças do produto selecionado.</p>
                </div>
            </div>
        </div>
    );
};
export default LicenseImport;
