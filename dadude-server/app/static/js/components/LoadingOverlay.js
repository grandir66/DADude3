// Loading Overlay Component per Vue.js 3
const LoadingOverlay = {
    data() {
        return {
            isLoading: false,
            loadingText: 'Caricamento...'
        }
    },
    mounted() {
        // Esponi metodi globali
        window.showLoading = this.show;
        window.hideLoading = this.hide;
        window.setLoadingText = this.setText;
    },
    methods: {
        show(text = 'Caricamento...') {
            this.loadingText = text;
            this.isLoading = true;
        },
        hide() {
            this.isLoading = false;
        },
        setText(text) {
            this.loadingText = text;
        }
    },
    template: `
        <transition name="fade">
            <div v-if="isLoading" class="loading-overlay">
                <div class="loading-content">
                    <div class="spinner-border text-primary mb-3" role="status" style="width: 3rem; height: 3rem;">
                        <span class="visually-hidden">Caricamento...</span>
                    </div>
                    <p class="text-white mb-0">{{ loadingText }}</p>
                </div>
            </div>
        </transition>
    `
};

