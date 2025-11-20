export interface LogEntry {
    timestamp: string;
    message: string;
    stack?: string;
    type: 'APP_ERROR' | 'API_ERROR' | 'INFO';
}

const logs: LogEntry[] = [];
const MAX_LOGS = 100;

const LogService = {
    add: (message: string, stack?: string, type: 'APP_ERROR' | 'API_ERROR' | 'INFO' = 'INFO') => {
        if (!message) return;
        const entry: LogEntry = {
            timestamp: new Date().toISOString(),
            message,
            stack: stack || (new Error()).stack,
            type,
        };
        logs.unshift(entry);
        if (logs.length > MAX_LOGS) {
            logs.pop();
        }
        console.error(`[LOG - ${type}]`, message, stack);
    },
    get: (): LogEntry[] => [...logs],
    clear: () => {
        logs.length = 0;
    },
    init: () => {
        const originalOnError = window.onerror;
        window.onerror = (message, source, lineno, colno, error) => {
            LogService.add(String(message), error?.stack || `at ${source}:${lineno}:${colno}`, 'APP_ERROR');
            if (originalOnError) {
                return originalOnError.call(window, message, source, lineno, colno, error);
            }
            return false;
        };

        const originalOnUnhandledRejection = window.onunhandledrejection;
        window.onunhandledrejection = (event) => {
            LogService.add(event.reason?.message || 'Unhandled promise rejection', event.reason?.stack, 'APP_ERROR');
             if (originalOnUnhandledRejection) {
                return originalOnUnhandledRejection.call(window, event);
            }
        };
        LogService.add("Sistema de logs inicializado.", undefined, 'INFO');
    }
};

export default LogService;
