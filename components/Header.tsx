import React, { useState } from 'react';
import { User } from '../types';
import Icon from './common/Icon';
import ProfileModal from './ProfileModal';

interface HeaderProps {
  pageTitle: string;
  user: User;
  onLogout: () => void;
  toggleTheme: () => void;
  isDarkMode: boolean;
  setIsSidebarOpen: (isOpen: boolean) => void;
  onUserUpdate: (updatedUser: User) => void;
}

const Header: React.FC<HeaderProps> = ({ pageTitle, user, onLogout, toggleTheme, isDarkMode, setIsSidebarOpen, onUserUpdate }) => {
  const [isProfileMenuOpen, setIsProfileMenuOpen] = useState(false);
  const [isProfileModalOpen, setIsProfileModalOpen] = useState(false);

  const handleSaveProfile = (updatedUser: User) => {
    onUserUpdate(updatedUser);
    // Here you would typically also make an API call to save the user data
    console.log("Profile saved", updatedUser);
    setIsProfileModalOpen(false);
  };


  return (
    <>
      <header className="h-20 bg-white dark:bg-dark-card shadow-md flex items-center justify-between px-4 sm:px-6 flex-shrink-0 z-10">
        <div className="flex items-center">
            <button
                onClick={() => setIsSidebarOpen(true)}
                className="lg:hidden mr-4 text-gray-600 dark:text-gray-300"
                aria-label="Open sidebar"
            >
                <Icon name="Menu" size={24} />
            </button>
          <h2 className="text-xl sm:text-2xl font-bold text-brand-dark dark:text-dark-text-primary hidden sm:block">{pageTitle}</h2>
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={toggleTheme}
            className="text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 p-2 rounded-full"
            title={isDarkMode ? 'Mudar para tema claro' : 'Mudar para tema escuro'}
          >
            <Icon name={isDarkMode ? 'Sun' : 'Moon'} size={20} />
          </button>
          <div className="relative">
            <button onClick={() => setIsProfileMenuOpen(!isProfileMenuOpen)} className="flex items-center gap-2">
              <img
                src={user.avatarUrl || `https://ui-avatars.com/api/?name=${encodeURIComponent(user.realName)}&background=3498db&color=fff`}
                alt="User Avatar"
                className="w-10 h-10 rounded-full object-cover border-2 border-brand-primary"
              />
              <span className="hidden md:inline font-semibold text-gray-700 dark:text-dark-text-secondary">{user.realName}</span>
              <Icon name={isProfileMenuOpen ? "ChevronUp" : "ChevronDown"} size={16} className="text-gray-500" />
            </button>
            {isProfileMenuOpen && (
              <div
                className="absolute right-0 mt-2 w-48 bg-white dark:bg-dark-card rounded-md shadow-lg py-1 z-20 border dark:border-dark-border"
                onMouseLeave={() => setIsProfileMenuOpen(false)}
              >
                <button
                   onClick={() => {
                      setIsProfileModalOpen(true);
                      setIsProfileMenuOpen(false);
                   }}
                   className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center gap-2"
                >
                    <Icon name="User" size={16}/> Meu Perfil
                </button>
                <button
                  onClick={onLogout}
                  className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center gap-2"
                >
                  <Icon name="LogOut" size={16} />
                  Sair
                </button>
              </div>
            )}
          </div>
        </div>
      </header>
      {isProfileModalOpen && <ProfileModal user={user} onClose={() => setIsProfileModalOpen(false)} onSave={handleSaveProfile} />}
    </>
  );
};

export default Header;
