import React, { useState, useRef, useMemo } from 'react';
import { User, Equipment } from '../types';
import Icon from './common/Icon';
import { importEquipment } from '../services/apiService';

type PartialEquipment = Partial<Equipment>;

const FileUploadBox: React.FC<{
    title: string;
    icon: any;
    file: File | null;
    onFileChange: (event: React.ChangeEvent<HTMLInputElement>) => void;
    isLoading: boolean;
}> = ({ title, icon, file, onFileChange, isLoading }) => {
    const inputRef = useRef<HTMLInputElement>(null);

    return (
        <div className="bg-white dark:bg-dark-card p-6 rounded-lg shadow-md border-l-4 border-brand-primary">
            <div className="flex items-center mb-3">
                <Icon name={icon} size={24} className="text-brand-primary mr-3" />
                <h3 className="text-xl font-bold text-brand-secondary dark:text-dark-text-primary">{title}</h3>
            </div>
            <input
                type="file"
                ref={inputRef}
                onChange={onFileChange}
                accept=".csv"
                className="hidden"
                disabled={isLoading}
            />
            <button
                onClick={() => inputRef.current?.click()}
                disabled={isLoading}
                className="w-full bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-dark-text-secondary px-4 py-3 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
                <Icon name="Upload" size={18} />
                <span>{file ? 'Trocar Arquivo' : 'Selecionar Arquivo CSV'}</span>
            </button>
            {file && (
                <div className="mt-3 text-sm text-gray-600 dark:text-dark-text-secondary">
                    <p><strong>Arquivo:</strong> {file.name}</p>
                </div>
            )}
        </div>
    );
};

const DataConsolidation: React.FC<{ currentUser: User }> = ({ currentUser }) => {
    const [baseFile, setBaseFile] = useState<File | null>(null);
    const [absoluteFile, setAbsoluteFile] = useState<File | null>(null);
    const [consolidatedData, setConsolidatedData] = useState<PartialEquipment[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [isSaving, setIsSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [searchTerm, setSearchTerm] = useState('');

    const splitCsvLine = (line: string): string[] => {
        const result: string[] = [];
        let current = '';
        let inQuote = false;
        // Handle comma as separator
        const separator = ',';
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

    const parseCsv = (fileText: string, mappings: { [key: string]: keyof Equipment }): PartialEquipment[] => {
        const lines = fileText.trim().split(/\r\n|\n/);
        if (lines.length < 2) throw new Error("O arquivo CSV deve conter um cabeçalho e pelo menos uma linha de dados.");

        const headerLine = lines[0].endsWith(',') ? lines[0].slice(0, -1) : lines[0];
        const header = splitCsvLine(headerLine).map(h => h.trim().toUpperCase());
        const rows = lines.slice(1);

        return rows.map(row => {
            if (!row.trim()) return null;

            const values = splitCsvLine(row);
            const entry: PartialEquipment = {};

            header.forEach((colName, index) => {
                const normalizedColName = colName.replace(/[\s/]+/g, '').toUpperCase();
                const mappedKey = mappings[normalizedColName] || mappings[colName.toUpperCase()];
                if (mappedKey && index < values.length) {
                    (entry as any)[mappedKey] = values[index]?.trim() || '';
                }
            });

            return entry;
        }).filter((item): item is PartialEquipment => {
            // Enforce that the serial number must exist and be non-empty for an item to be valid.
            return item !== null && !!item.serial && item.serial.trim() !== '';
        });
    };

    const handleConsolidate = async () => {
        if (!baseFile || !absoluteFile) return;

        setIsLoading(true);
        setError(null);
        setConsolidatedData([]);

        try {
            const baseText = await baseFile.text();
            const absoluteText = await absoluteFile.text();
            
            const baseMappings: { [key: string]: keyof Equipment } = {
                'EQUIPAMENTO': 'equipamento', 'GARANTIA': 'garantia', 'SERIAL': 'serial',
                'USUÁRIOATUAL': 'usuarioAtual', 'USUÁRIOANTERIOR': 'usuarioAnterior', 'LOCAL': 'local', 'SETOR': 'setor',
                'DATAENTREGAOUSUÁRIO': 'dataEntregaUsuario', 'STATUS': 'status', 'DATADEDEVOLUÇÃO': 'dataDevolucao',
                'TIPO': 'tipo', 'NOTADECOMPRA': 'notaCompra', 'NOTA/PLK&M': 'notaPlKm',
                'TERMODERESPONSABILIDADE': 'termoResponsabilidade', 'FOTO': 'foto', 'QRCODE': 'qrCode'
            };

            const absoluteMappings: { [key: string]: keyof Equipment } = {
                'NOMEDODISPOSITIVO': 'equipamento', 'NÚMERODESÉRIE': 'serial',
                'NOMEDOUSUÁRIOATUAL': 'usuarioAtual', 'MARCA': 'brand', 'MODELO': 'model'
            };

            const baseData = parseCsv(baseText, baseMappings);
            const absoluteData = parseCsv(absoluteText, absoluteMappings);
            
            const absoluteMap = new Map<string, PartialEquipment>();
            absoluteData.forEach(item => {
                 // The filter in parseCsv ensures item.serial is a non-empty string
                absoluteMap.set(item.serial!.toUpperCase(), item);
            });

            const finalData: PartialEquipment[] = [];
            const mergedSerials = new Set<string>();

            baseData.forEach(baseItem => {
                let mergedItem = { ...baseItem };
                 // The filter in parseCsv ensures baseItem.serial is a non-empty string
                const serial = baseItem.serial!.toUpperCase();
                if (absoluteMap.has(serial)) {
                    const absoluteItem = absoluteMap.get(serial)!;
                    // Prioritize data from Absolute report (more current) for overlapping fields
                    mergedItem = { ...baseItem, ...absoluteItem };
                    mergedSerials.add(serial);
                }
                finalData.push(mergedItem);
            });
            
            absoluteData.forEach(absoluteItem => {
                // The filter in parseCsv ensures absoluteItem.serial is a non-empty string
                const serial = absoluteItem.serial!.toUpperCase();
                if (!mergedSerials.has(serial)) {
                    finalData.push(absoluteItem);
                }
            });

            setConsolidatedData(finalData);

        } catch (e: any) {
            setError(`Falha ao processar arquivos: ${e.message}`);
            console.error(e);
        } finally {
            setIsLoading(false);
        }
    };
    
    const handleSaveToSystem = async () => {
        if (consolidatedData.length === 0) return;
        if (!window.confirm(`Esta ação substituirá TODO o inventário de equipamentos por ${consolidatedData.length} novos itens consolidados. Esta ação é irreversível. Deseja continuar?`)) return;
        
        setIsSaving(true);
        setError(null);
        try {
            const dataToSave = consolidatedData.map(item => ({...item, id: undefined})) as Omit<Equipment, 'id'>[];
            // FIX: Pass currentUser.username to importEquipment for authentication.
            await importEquipment(dataToSave, currentUser.username);
            alert('Inventário consolidado e salvo com sucesso! A aplicação será recarregada para refletir as mudanças.');
            window.location.reload();
        } catch (e: any) {
            setError(`Falha ao salvar no sistema: ${e.message}`);
        } finally {
            setIsSaving(false);
        }
    };

    const filteredData = useMemo(() => {
        if (!searchTerm) return consolidatedData;
        const lowercasedFilter = searchTerm.toLowerCase();
        return consolidatedData.filter(item => {
            return Object.values(item).some(value =>
                String(value).toLowerCase().includes(lowercasedFilter)
            );
        });
    }, [searchTerm, consolidatedData]);

    const tableHeaders: (keyof Equipment)[] = ['equipamento', 'serial', 'usuarioAtual', 'local', 'setor', 'status', 'brand', 'model'];

    return (
        <div className="bg-white dark:bg-dark-card p-6 rounded-lg shadow-md">
            <h3 className="text-xl font-bold text-brand-secondary dark:text-dark-text-primary mb-2 border-b dark:border-dark-border pb-2">Ferramenta de Consolidação de Inventário</h3>
            <p className="text-sm text-gray-500 dark:text-dark-text-secondary mb-4">
                Faça o upload da Planilha Base e do Relatório Absolute para consolidar os dados. O resultado substituirá o inventário atual do sistema.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <FileUploadBox
                    title="1. Planilha Base"
                    icon="Sheet"
                    file={baseFile}
                    onFileChange={(e) => setBaseFile(e.target.files ? e.target.files[0] : null)}
                    isLoading={isLoading || isSaving}
                />
                <FileUploadBox
                    title="2. Relatório Absolute"
                    icon="FileText"
                    file={absoluteFile}
                    onFileChange={(e) => setAbsoluteFile(e.target.files ? e.target.files[0] : null)}
                    isLoading={isLoading || isSaving}
                />
            </div>

            <div className="mt-6 flex justify-center">
                <button
                    onClick={handleConsolidate}
                    disabled={!baseFile || !absoluteFile || isLoading || isSaving}
                    className="bg-brand-primary text-white px-8 py-3 rounded-lg hover:bg-blue-700 disabled:bg-gray-400 flex items-center justify-center gap-2 text-lg font-semibold"
                >
                    {isLoading ? <Icon name="LoaderCircle" className="animate-spin" /> : <Icon name="Combine" />}
                    {isLoading ? 'Processando...' : '1. Consolidar Dados'}
                </button>
            </div>

            {error && <div className="mt-4 bg-red-100 border-l-4 border-red-500 text-red-700 p-4" role="alert"><p>{error}</p></div>}
            
            {consolidatedData.length > 0 && !isLoading && (
                 <div className="mt-6">
                    <h3 className="text-xl font-bold text-brand-dark dark:text-dark-text-primary mb-4">
                        Pré-visualização ({filteredData.length} de {consolidatedData.length} itens)
                    </h3>
                     <input
                        type="text"
                        placeholder="Buscar nos resultados..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full p-2 mb-4 border dark:border-dark-border rounded-md bg-white dark:bg-gray-800"
                    />
                    <div className="overflow-x-auto max-h-96 border dark:border-dark-border rounded-lg">
                        <table className="w-full text-sm text-left text-gray-700 dark:text-dark-text-secondary">
                             <thead className="text-xs text-gray-800 dark:text-dark-text-primary uppercase bg-gray-100 dark:bg-gray-900/50 sticky top-0">
                                <tr>
                                    {tableHeaders.map(header => (
                                        <th key={header} scope="col" className="px-6 py-3 capitalize">{String(header).replace(/([A-Z])/g, ' $1')}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-dark-card">
                                {filteredData.map((item, index) => (
                                    <tr key={item.serial || item.patrimonio || index} className="border-b dark:border-dark-border last:border-0 hover:bg-gray-50 dark:hover:bg-gray-700">
                                        {tableHeaders.map(header => (
                                            <td key={header} className="px-6 py-4 whitespace-nowrap">{item[header] || 'N/A'}</td>
                                        ))}
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
                            {isSaving ? 'Salvando...' : '2. Salvar e Substituir Inventário'}
                        </button>
                    </div>
                 </div>
            )}
        </div>
    );
};

export default DataConsolidation;