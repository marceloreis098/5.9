
import React, { useState, useRef, useMemo } from 'react';
import { User, Equipment } from '../types';
import Icon from './common/Icon';
import { periodicUpdateEquipment } from '../services/apiService';

type PartialEquipment = Partial<Equipment>;

interface PeriodicUpdateProps {
    currentUser: User;
    onUpdateSuccess: () => void;
}

const PeriodicUpdate: React.FC<PeriodicUpdateProps> = ({ currentUser, onUpdateSuccess }) => {
    const [csvFile, setCsvFile] = useState<File | null>(null);
    const [parsedData, setParsedData] = useState<PartialEquipment[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [isSaving, setIsSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [searchTerm, setSearchTerm] = useState('');
    const fileInputRef = useRef<HTMLInputElement>(null);

    const splitCsvLine = (line: string, separator: string): string[] => {
        const result: string[] = [];
        let current = '';
        let inQuote = false;
        for (let i = 0; i < line.length; i++) {
            const char = line[i];
            if (char === '"') {
                inQuote = !inQuote;
            } else if (char === separator && !inQuote) {
                result.push(current.trim().replace(/^"|"$/g, ''));
                current = '';
            } else {
                current += char;
            }
        }
        result.push(current.trim().replace(/^"|"$/g, ''));
        return result;
    };

    const normalizeHeader = (header: string): string => {
        // Remove accents, spaces, and special chars to make mapping robust
        return header
            .toUpperCase()
            .normalize("NFD").replace(/[\u0300-\u036f]/g, "") // Remove accents
            .replace(/[^A-Z0-9]/g, ""); // Remove spaces and symbols
    };

    const parseCsv = (fileText: string): PartialEquipment[] => {
        const cleanText = fileText.replace(/^\uFEFF/, ''); // Remove BOM
        const lines = cleanText.trim().split(/\r\n|\n/);
        if (lines.length < 2) throw new Error("O arquivo CSV deve conter um cabeçalho e dados.");

        const headerLine = lines[0];
        // Detect separator
        const separator = (headerLine.match(/;/g) || []).length > (headerLine.match(/,/g) || []).length ? ';' : ',';
        
        const rawHeaders = splitCsvLine(headerLine, separator);
        const header = rawHeaders.map(h => normalizeHeader(h));

        // Mapping based on normalized headers (e.g., "Número de série" becomes "NUMERODESERIE")
        const mappings: { [key: string]: keyof Equipment } = {
            'NOMEDODISPOSITIVO': 'equipamento',
            'DISPOSITIVO': 'equipamento',
            'EQUIPAMENTO': 'equipamento',
            
            'NUMERODESERIE': 'serial',
            'SERIAL': 'serial',
            
            'NOMEDOUSUARIOATUAL': 'usuarioAtual',
            'USUARIOATUAL': 'usuarioAtual',
            'USUARIO': 'usuarioAtual',
            
            'MARCA': 'brand',
            'MODELO': 'model',
            
            'EMAILDOCOLABORADOR': 'emailColaborador',
            'EMAIL': 'emailColaborador',
            
            'IDENTIFICADOR': 'identificador',
            'NOMEDOSO': 'nomeSO',
            'SO': 'nomeSO',
            
            'MEMORIAFISICATOTAL': 'memoriaFisicaTotal',
            'MEMORIA': 'memoriaFisicaTotal',
            
            'GRUPODEPOLITICAS': 'grupoPoliticas',
            'POLITICAS': 'grupoPoliticas',
            
            'PAIS': 'pais',
            'CIDADE': 'cidade',
            'ESTADOPROVINCIA': 'estadoProvincia',
            'ESTADO': 'estadoProvincia',
            
            'LOCAL': 'local',
            'SETOR': 'setor'
        };

        return lines.slice(1).map(row => {
            if (!row.trim()) return null;
            const values = splitCsvLine(row, separator);
            const entry: PartialEquipment = {};
            
            header.forEach((colName, index) => {
                const mappedKey = mappings[colName];
                if (mappedKey && index < values.length) {
                    const value = values[index]?.trim();
                    if (value) {
                         (entry as any)[mappedKey] = value;
                    }
                }
            });

            // Basic validation: Serial is required
            if (!entry.serial || entry.serial.trim() === '') return null;
            
            return entry;
        }).filter((item): item is PartialEquipment => item !== null);
    };

    const handleParse = async () => {
        if (!csvFile) return;
        setIsLoading(true);
        setError(null);
        setParsedData([]);
        try {
            const text = await csvFile.text();
            const data = parseCsv(text);
            setParsedData(data);
            if (data.length === 0) {
                setError("Nenhum dado válido encontrado. Verifique se as colunas obrigatórias (ex: Número de série) existem.");
            }
        } catch (e: any) {
            setError(`Falha ao processar arquivo: ${e.message}`);
        } finally {
            setIsLoading(false);
        }
    };

    const handleSaveToSystem = async () => {
        if (parsedData.length === 0) return;
        if (!window.confirm(`Esta ação irá atualizar ${parsedData.length} registros no inventário (adicionando novos e atualizando existentes baseados no Serial). Deseja continuar?`)) return;
        
        setIsSaving(true);
        setError(null);
        try {
            const result = await periodicUpdateEquipment(parsedData, currentUser.username);
            if (result.success) {
                alert(result.message);
                onUpdateSuccess();
                setParsedData([]);
                setCsvFile(null);
                if (fileInputRef.current) fileInputRef.current.value = '';
            } else {
                setError(`Falha ao salvar no sistema: ${result.message}`);
            }
        } catch (e: any) {
            let message = e.message || "Erro desconhecido";
            if (message.includes('Failed to fetch')) {
                message = "Erro de conexão com a API. Verifique se o servidor está rodando.";
            }
            setError(`Falha ao salvar no sistema: ${message}`);
        } finally {
            setIsSaving(false);
        }
    };

    const filteredData = useMemo(() => {
        if (!searchTerm) return parsedData;
        const lowercasedFilter = searchTerm.toLowerCase();
        return parsedData.filter(item => Object.values(item).some(value =>
            String(value).toLowerCase().includes(lowercasedFilter)
        ));
    }, [searchTerm, parsedData]);

    const tableHeaders: (keyof Equipment)[] = ['equipamento', 'serial', 'usuarioAtual', 'brand', 'model', 'grupoPoliticas'];

    return (
        <div className="bg-white dark:bg-dark-card p-6 rounded-lg shadow-md">
            <h3 className="text-xl font-bold text-brand-secondary dark:text-dark-text-primary mb-2 border-b dark:border-dark-border pb-2">Atualização Periódica de Inventário</h3>
            <p className="text-sm text-gray-500 dark:text-dark-text-secondary mb-4">
                Faça o upload do "Relatório Absolute" para mesclar e atualizar os dados do inventário. Itens existentes serão atualizados e novos serão adicionados.
            </p>

            <div className="bg-white dark:bg-dark-card p-6 rounded-lg shadow-md border-l-4 border-brand-primary">
                <div className="flex items-center mb-3">
                    <Icon name="FileText" size={24} className="text-brand-primary mr-3" />
                    <h3 className="text-xl font-bold text-brand-secondary dark:text-dark-text-primary">Relatório Absolute</h3>
                </div>
                <input type="file" ref={fileInputRef} onChange={(e) => setCsvFile(e.target.files ? e.target.files[0] : null)} accept=".csv" className="hidden" disabled={isLoading || isSaving} />
                <button onClick={() => fileInputRef.current?.click()} disabled={isLoading || isSaving} className="w-full bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-dark-text-secondary px-4 py-3 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 flex items-center justify-center gap-2 transition-colors disabled:opacity-50">
                    <Icon name="Upload" size={18} />
                    <span>{csvFile ? 'Trocar Arquivo' : 'Selecionar Arquivo CSV'}</span>
                </button>
                {csvFile && <p className="mt-3 text-sm text-gray-600 dark:text-dark-text-secondary"><strong>Arquivo:</strong> {csvFile.name}</p>}
            </div>

            <div className="mt-6 flex justify-center">
                <button onClick={handleParse} disabled={!csvFile || isLoading || isSaving} className="bg-brand-primary text-white px-8 py-3 rounded-lg hover:bg-blue-700 disabled:bg-gray-400 flex items-center justify-center gap-2 text-lg font-semibold">
                    {isLoading ? <Icon name="LoaderCircle" className="animate-spin" /> : <Icon name="Search" />}
                    {isLoading ? 'Analisando...' : '1. Analisar Dados'}
                </button>
            </div>

            {error && <div className="mt-4 bg-red-100 border-l-4 border-red-500 text-red-700 p-4" role="alert"><p>{error}</p></div>}

            {parsedData.length > 0 && !isLoading && (
                 <div className="mt-6 animate-fade-in">
                    <h3 className="text-xl font-bold text-brand-dark dark:text-dark-text-primary mb-4">Pré-visualização da Atualização ({filteredData.length} de {parsedData.length} itens)</h3>
                    <input type="text" placeholder="Buscar nos resultados..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} className="w-full p-2 mb-4 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800" />
                    <div className="overflow-x-auto max-h-96 border dark:border-dark-border rounded-lg">
                        <table className="w-full text-sm text-left text-gray-700 dark:text-dark-text-secondary">
                             <thead className="text-xs text-gray-800 dark:text-dark-text-primary uppercase bg-gray-100 dark:bg-gray-900/50 sticky top-0">
                                <tr>{tableHeaders.map(header => <th key={header} scope="col" className="px-6 py-3 capitalize">{String(header).replace(/([A-Z])/g, ' $1')}</th>)}</tr>
                            </thead>
                            <tbody className="bg-white dark:bg-dark-card">
                                {filteredData.map((item, index) => (
                                    <tr key={item.serial || index} className="border-b dark:border-dark-border last:border-0 hover:bg-gray-50 dark:hover:bg-gray-700">
                                        {tableHeaders.map(header => <td key={header} className="px-6 py-4 whitespace-nowrap">{item[header] || 'N/A'}</td>)}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    <div className="mt-6 flex justify-end">
                        <button
                            onClick={handleSaveToSystem}
                            disabled={isSaving}
                            className="bg-green-600 text-white px-8 py-3 rounded-lg hover:bg-green-700 disabled:bg-gray-400 flex items-center justify-center gap-2 text-lg font-semibold"
                        >
                            {isSaving ? <Icon name="LoaderCircle" className="animate-spin" /> : <Icon name="Save" />}
                            {isSaving ? 'Salvando...' : '2. Salvar e Atualizar Inventário'}
                        </button>
                    </div>
                 </div>
            )}
        </div>
    );
};

export default PeriodicUpdate;
