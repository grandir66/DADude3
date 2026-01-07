// App Vue.js principale per DaDude
const { createApp } = Vue;

// Utility per toast semplificati
window.toastSuccess = (message) => {
    if (window.showToast) {
        window.showToast(message, 'success', 4000);
    } else {
        console.log('✅', message);
    }
};

window.toastError = (message) => {
    if (window.showToast) {
        window.showToast(message, 'error', 6000);
    } else {
        console.error('❌', message);
    }
};

window.toastWarning = (message) => {
    if (window.showToast) {
        window.showToast(message, 'warning', 5000);
    } else {
        console.warn('⚠️', message);
    }
};

window.toastInfo = (message) => {
    if (window.showToast) {
        window.showToast(message, 'info', 4000);
    } else {
        console.info('ℹ️', message);
    }
};

// Inizializza app Vue quando il DOM è pronto
document.addEventListener('DOMContentLoaded', () => {
    const app = createApp({
        components: {
            ToastNotifications,
            LoadingOverlay,
            DataTable: window.DataTable || DataTable,
            AnimatedCounter
        }
    });
    
    app.mount('#vue-app');
});

