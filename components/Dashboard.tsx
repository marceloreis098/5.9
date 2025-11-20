
import React, { useState, useEffect, lazy, Suspense } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';
import { getEquipment, getLicenses, getSettings } from '../services/apiService';
import { Equipment, License, Page, User, UserRole, AppSettings } from '../types';
import Icon from './common/Icon';

const ApprovalQueue = lazy(() => import('./ApprovalQueue'));

interface DashboardProps {
    setActivePage: (page: Page) => void;
    currentUser: User;
}

const PIE_COLORS = ['#3498db', '#2ecc71', '#f1c40f', '#e74c3c', '#9b59b6', '#1abc9c', '#d35400'];

const InventoryStatusPanel: React.FC<{ settings: Partial<AppSettings>; setActivePage: (page: Page) => void; }> = ({ settings, setActivePage }) => {
    if (settings.hasInitialConsolidationRun === undefined) {
        return null; // Don't show while loading
    }

    if (!settings.hasInitialConsolidationRun) {
        return (
            <div className="bg-yellow-100 dark:bg-yellow-900/30 border-l-4 border-yellow-500 text-yellow-800 dark:text-yellow-200 p-4 rounded-lg shadow-md flex flex-col sm:flex-row justify-between items-center gap-4">
                <div className="flex items-center gap-3">
                    <Icon name="TriangleAlert" size={24} />
                    <div>
                        <h4 className="font-bold">Ação Necessária</h4>
                        <p>A consolidação inicial do inventário de equipamentos está pendente.</p>
                    </div>
                </div>
                <button onClick={() => setActivePage('Configurações')} className="bg-yellow-500 text-white font-bold py-2 px-4 rounded hover:bg-yellow-600 transition-colors flex-shrink-0">
                    Realizar Consolidação
                </button>
            </div>
        );
    }

    const lastUpdate = settings.lastAbsoluteUpdateTimestamp ? new Date(settings.lastAbsoluteUpdateTimestamp) : null;
    const isValidDate = lastUpdate && !isNaN(lastUpdate.getTime());
    const now = new Date();
    const hoursDiff = isValidDate ? (now.getTime() - lastUpdate.getTime()) / (1000 * 60 * 60) : Infinity;
    const isUpdatePending = hoursDiff > 48;

    return (
        <div className={`p-4 rounded-lg shadow-md flex flex-col sm:flex-row justify-between items-center gap-4 ${isUpdatePending ? 'bg-orange-100 dark:bg-orange-900/30 border-l-4 border-orange-500 text-orange-800 dark:text-orange-200' : 'bg-green-100 dark:bg-green-900/30 border-l-4 border-green-500 text-green-800 dark:text-green-200'}`}>
             <div className="flex items-center gap-3">
                <Icon name={isUpdatePending ? "History" : "CircleCheck"} size={24} />
                <div>
                    <h4 className="font-bold">Status da Atualização do Inventário</h4>
                    {isValidDate ? (
                        <p>Última atualização: {lastUpdate.toLocaleString('pt-BR')}</p>
                    ) : (
                        <p>Nenhuma atualização registrada.</p>
                    )}
                </div>
            </div>
            {isUpdatePending && (
                 <button onClick={() => setActivePage('Configurações')} className="bg-orange-500 text-white font-bold py-2 px-4 rounded hover:bg-orange-600 transition-colors flex-shrink-0">
                    Atualizar Agora
                </button>
            )}
        </div>
    );
};


const Dashboard: React.FC<DashboardProps> = ({setActivePage, currentUser}) => {
  const [equipment, setEquipment] = useState<Equipment[]>([]);
  const [licenses, setLicenses] = useState<License[]>([]);
  const [settings, setSettings] = useState<Partial<AppSettings>>({});
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [equipmentData, licensesData, settingsData] = await Promise.all([
        getEquipment(currentUser),
        getLicenses(currentUser),
        currentUser.role === UserRole.Admin ? getSettings() : Promise.resolve({})
      ]);
      setEquipment(equipmentData);
      setLicenses(licensesData);
      setSettings(settingsData);
    } catch (error) {
      console.error("Failed to fetch dashboard data:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [currentUser]);

  const isDarkMode = document.documentElement.classList.contains('dark');
  const textColor = isDarkMode ? '#edf2f7' : '#333';
  const tooltipBackgroundColor = isDarkMode ? '#2d3748' : '#ffffff';
  const tooltipBorderColor = isDarkMode ? '#4a5568' : '#cccccc';
  
  // Stats calculation
  const totalEquipment = equipment.length;
  const statusCounts = equipment.reduce((acc, item) => {
      const status = (item.status || 'Indefinido').toUpperCase();
      acc[status] = (acc[status] || 0) + 1;
      return acc;
  }, {} as {[key: string]: number});
  
  const expiringLicenses = licenses.filter(l => {
      if (!l.dataExpiracao || l.dataExpiracao === 'N/A') return false;
      const expDate = new Date(l.dataExpiracao);
      const today = new Date();
      const thirtyDaysFromNow = new Date();
      thirtyDaysFromNow.setDate(today.getDate() + 30);
      return expDate > today && expDate <= thirtyDaysFromNow;
  }).length;


  const brandData = equipment.reduce((acc, item) => {
    const brandName = item.brand || 'Não especificado';
    const existingBrand = acc.find(d => d.name === brandName);
    if (existingBrand) {
      existingBrand.value += 1;
    } else {
      acc.push({ name: brandName, value: 1 });
    }
    return acc;
  }, [] as { name: string, value: number }[]).sort((a,b) => a.value - b.value);

  const statusData = Object.entries(statusCounts).map(([name, value]) => ({ name, value }));


  const StatCard = ({ icon, title, value, color, onClick }: { icon: any, title: string, value: string | number, color: string, onClick?: () => void }) => (
    <div className={`bg-white dark:bg-dark-card p-6 rounded-lg shadow-md flex items-center ${onClick ? 'cursor-pointer hover:shadow-lg transition-shadow' : ''}`} onClick={onClick}>
      <div className={`p-4 rounded-full ${color}`}>
        <Icon name={icon} size={24} className="text-white" />
      </div>
      <div className="ml-4">
        <p className="text-lg font-semibold text-gray-700 dark:text-dark-text-secondary">{title}</p>
        <p className="text-3xl font-bold text-gray-900 dark:text-dark-text-primary">{value}</p>
      </div>
    </div>
  );

  if (loading) {
    return (
      <div className="flex justify-center items-center h-full">
        <Icon name="LoaderCircle" className="animate-spin text-brand-primary" size={48} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
       {currentUser.role === UserRole.Admin && (
          <Suspense fallback={<div>Carregando...</div>}>
            <ApprovalQueue currentUser={currentUser} onAction={fetchData} />
            <InventoryStatusPanel settings={settings} setActivePage={setActivePage} />
          </Suspense>
       )}
      <h2 className="text-3xl font-bold text-brand-dark dark:text-dark-text-primary mt-6">Dashboard</h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard icon="Computer" title="Total de Itens" value={totalEquipment} color="bg-blue-500" onClick={() => setActivePage('Inventário de Equipamentos')} />
        <StatCard icon="Play" title="Em Uso" value={statusCounts['EM USO'] || 0} color="bg-status-active"/>
        <StatCard icon="Archive" title="Estoque" value={statusCounts['ESTOQUE'] || 0} color="bg-yellow-500" />
        <StatCard icon="Timer" title="Licenças Expirando" value={expiringLicenses} color="bg-red-500" onClick={() => setActivePage('Controle de Licenças')} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-dark-card p-6 rounded-lg shadow-md">
          <h3 className="text-xl font-semibold mb-4 text-brand-dark dark:text-dark-text-primary">Equipamentos por Status</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={statusData}>
              <XAxis dataKey="name" stroke={textColor} />
              <YAxis stroke={textColor} allowDecimals={false}/>
              <Tooltip cursor={{fill: 'rgba(128,128,128,0.1)'}} contentStyle={{ backgroundColor: tooltipBackgroundColor, borderColor: tooltipBorderColor }}/>
              <Legend wrapperStyle={{ color: textColor }} />
              <Bar dataKey="value" name="Total" fill="#8884d8">
                 {statusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                  ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="bg-white dark:bg-dark-card p-6 rounded-lg shadow-md">
          <h3 className="text-xl font-semibold mb-4 text-brand-dark dark:text-dark-text-primary">Equipamentos por Marca</h3>
          <ResponsiveContainer width="100%" height={300}>
             <BarChart layout="vertical" data={brandData} margin={{ top: 5, right: 20, left: 60, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={isDarkMode ? '#4a5568' : '#e0e0e0'}/>
                <XAxis type="number" stroke={textColor} allowDecimals={false} />
                <YAxis type="category" dataKey="name" stroke={textColor} width={80} tick={{ fontSize: 12, fill: textColor }} />
                <Tooltip cursor={{fill: 'rgba(128,128,128,0.1)'}} contentStyle={{ backgroundColor: tooltipBackgroundColor, borderColor: tooltipBorderColor }}/>
                <Bar dataKey="value" name="Quantidade" fill="#3498db" barSize={20}>
                    {brandData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
