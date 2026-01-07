// Toast Notifications Component per Vue.js 3
const ToastNotifications = {
    data() {
        return {
            toasts: []
        }
    },
    mounted() {
        // Esponi il metodo globale per mostrare toast
        window.showToast = this.showToast;
    },
    methods: {
        showToast(message, type = 'info', duration = 5000) {
            const id = Date.now() + Math.random();
            const toast = {
                id,
                message,
                type, // 'success', 'error', 'warning', 'info'
                duration
            };
            
            this.toasts.push(toast);
            
            // Auto-rimuovi dopo duration
            setTimeout(() => {
                this.removeToast(id);
            }, duration);
            
            return id;
        },
        removeToast(id) {
            const index = this.toasts.findIndex(t => t.id === id);
            if (index > -1) {
                this.toasts.splice(index, 1);
            }
        },
        getToastClass(type) {
            const classes = {
                'success': 'bg-success',
                'error': 'bg-danger',
                'warning': 'bg-warning text-dark',
                'info': 'bg-info'
            };
            return classes[type] || classes.info;
        },
        getToastIcon(type) {
            const icons = {
                'success': 'bi-check-circle-fill',
                'error': 'bi-x-circle-fill',
                'warning': 'bi-exclamation-triangle-fill',
                'info': 'bi-info-circle-fill'
            };
            return icons[type] || icons.info;
        }
    },
    template: `
        <div class="toast-container position-fixed top-0 end-0 p-3" style="z-index: 9999;">
            <transition-group name="toast" tag="div">
                <div
                    v-for="toast in toasts"
                    :key="toast.id"
                    :class="['toast show align-items-center text-white', getToastClass(toast.type)]"
                    role="alert"
                    aria-live="assertive"
                    aria-atomic="true"
                    style="min-width: 300px; margin-bottom: 0.5rem;"
                >
                    <div class="d-flex">
                        <div class="toast-body d-flex align-items-center">
                            <i :class="['bi me-2', getToastIcon(toast.type)]"></i>
                            <span>{{ toast.message }}</span>
                        </div>
                        <button
                            type="button"
                            class="btn-close btn-close-white me-2 m-auto"
                            @click="removeToast(toast.id)"
                            aria-label="Close"
                        ></button>
                    </div>
                </div>
            </transition-group>
        </div>
    `
};

