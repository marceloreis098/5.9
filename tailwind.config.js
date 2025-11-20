/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./{App,components,services,data,types}.tsx",
    "./components/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'brand-primary': '#3498db',
        'brand-secondary': '#2c3e50',
        'brand-light': '#ecf0f1',
        'brand-dark': '#1e2731',
        'status-active': '#27ae60',
        'status-maintenance': '#f39c12',
        'status-disabled': '#c0392b',
        // Dark theme colors
        'dark-bg': '#1a202c',
        'dark-card': '#2d3748',
        'dark-text-primary': '#edf2f7',
        'dark-text-secondary': '#a0aec0',
        'dark-border': '#4a5568',
      },
      keyframes: {
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'fade-in-up': {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'scale-in': {
          '0%': { transform: 'scale(0.95)', opacity: '0' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
      },
      animation: {
        'fade-in': 'fade-in 0.5s ease-out forwards',
        'fade-in-up': 'fade-in-up 0.5s ease-out forwards',
        'scale-in': 'scale-in 0.3s ease-out forwards',
      },
    },
  },
  plugins: [],
}