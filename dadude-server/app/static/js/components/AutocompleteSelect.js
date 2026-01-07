// AutocompleteSelect Component per Vue.js 3
// Dropdown autocompletamento/editabile con possibilità di aggiungere nuove voci

const AutocompleteSelect = {
    props: {
        modelValue: {
            type: String,
            default: ''
        },
        options: {
            type: Array,
            default: () => []
        },
        placeholder: {
            type: String,
            default: 'Seleziona o inserisci...'
        },
        allowNew: {
            type: Boolean,
            default: true
        },
        apiEndpoint: {
            type: String,
            default: null
        },
        loading: {
            type: Boolean,
            default: false
        }
    },
    emits: ['update:modelValue', 'new-value'],
    data() {
        return {
            searchQuery: '',
            isOpen: false,
            filteredOptions: [],
            isLoading: false,
            optionsLoaded: false
        }
    },
    computed: {
        displayValue() {
            if (this.modelValue && this.optionsLoaded) {
                const option = this.options.find(opt => opt === this.modelValue || (typeof opt === 'object' && opt.value === this.modelValue));
                if (option) {
                    return typeof option === 'string' ? option : option.label || option.value;
                }
            }
            return this.modelValue || '';
        },
        showNewOption() {
            return this.allowNew && 
                   this.searchQuery && 
                   this.searchQuery.trim() !== '' &&
                   !this.filteredOptions.some(opt => {
                       const val = typeof opt === 'string' ? opt : (opt.value || opt.label);
                       return val.toLowerCase() === this.searchQuery.toLowerCase();
                   });
        }
    },
    watch: {
        searchQuery() {
            this.filterOptions();
        },
        options() {
            this.filterOptions();
        },
        apiEndpoint: {
            immediate: true,
            handler() {
                if (this.apiEndpoint && !this.optionsLoaded) {
                    this.loadOptions();
                }
            }
        }
    },
    mounted() {
        this.filterOptions();
        // Carica opzioni da API se endpoint specificato
        if (this.apiEndpoint && !this.optionsLoaded) {
            this.loadOptions();
        }
        // Chiudi dropdown quando si clicca fuori
        document.addEventListener('click', this.handleClickOutside);
    },
    beforeUnmount() {
        document.removeEventListener('click', this.handleClickOutside);
    },
    methods: {
        async loadOptions() {
            if (!this.apiEndpoint || this.isLoading) return;
            
            this.isLoading = true;
            try {
                const response = await fetch(this.apiEndpoint);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}`);
                }
                const data = await response.json();
                // Estrai valori dalla risposta API
                const values = data.values || (Array.isArray(data) ? data : []);
                // Aggiorna opzioni (merge con quelle esistenti)
                const existingValues = this.options.map(opt => typeof opt === 'string' ? opt : (opt.value || opt.label));
                const newValues = values.filter(v => !existingValues.includes(v));
                this.$emit('options-loaded', [...this.options, ...newValues]);
                this.optionsLoaded = true;
            } catch (e) {
                console.error('Error loading options from API:', e);
            } finally {
                this.isLoading = false;
            }
        },
        filterOptions() {
            if (!this.searchQuery) {
                this.filteredOptions = this.options;
                return;
            }
            
            const query = this.searchQuery.toLowerCase();
            this.filteredOptions = this.options.filter(opt => {
                const val = typeof opt === 'string' ? opt : (opt.label || opt.value || '');
                return val.toLowerCase().includes(query);
            });
        },
        selectOption(option) {
            const value = typeof option === 'string' ? option : (option.value || option.label);
            this.$emit('update:modelValue', value);
            this.searchQuery = '';
            this.isOpen = false;
        },
        addNewValue() {
            if (!this.searchQuery || !this.searchQuery.trim()) return;
            
            const newValue = this.searchQuery.trim();
            this.$emit('update:modelValue', newValue);
            this.$emit('new-value', newValue);
            this.searchQuery = '';
            this.isOpen = false;
        },
        handleClickOutside(event) {
            if (!this.$el.contains(event.target)) {
                this.isOpen = false;
            }
        },
        toggleDropdown() {
            this.isOpen = !this.isOpen;
            if (this.isOpen && this.apiEndpoint && !this.optionsLoaded) {
                this.loadOptions();
            }
        }
    },
    template: `
        <div class="autocomplete-select position-relative">
            <div class="input-group">
                <input 
                    type="text"
                    class="form-control"
                    :value="displayValue"
                    @input="searchQuery = $event.target.value; isOpen = true"
                    @focus="isOpen = true"
                    @keydown.enter.prevent="showNewOption ? addNewValue() : (filteredOptions.length > 0 ? selectOption(filteredOptions[0]) : null)"
                    @keydown.escape="isOpen = false"
                    :placeholder="placeholder"
                />
                <button 
                    class="btn btn-outline-secondary" 
                    type="button"
                    @click="toggleDropdown"
                    :disabled="loading || isLoading"
                >
                    <i class="bi" :class="isLoading ? 'bi-arrow-repeat spin' : (isOpen ? 'bi-chevron-up' : 'bi-chevron-down')"></i>
                </button>
            </div>
            
            <div v-if="isOpen" class="dropdown-menu show position-absolute w-100" style="max-height: 300px; overflow-y: auto; z-index: 1000;">
                <div v-if="isLoading" class="dropdown-item text-muted">
                    <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                    Caricamento...
                </div>
                <div v-else-if="filteredOptions.length === 0 && !showNewOption" class="dropdown-item text-muted">
                    Nessun risultato
                </div>
                <template v-else>
                    <a 
                        v-for="(option, index) in filteredOptions" 
                        :key="index"
                        class="dropdown-item" 
                        href="#"
                        @click.prevent="selectOption(option)"
                    >
                        {{ typeof option === 'string' ? option : (option.label || option.value) }}
                    </a>
                    <div v-if="showNewOption" class="dropdown-divider"></div>
                    <a 
                        v-if="showNewOption"
                        class="dropdown-item text-primary" 
                        href="#"
                        @click.prevent="addNewValue"
                    >
                        <i class="bi bi-plus-circle"></i> Aggiungi "{{ searchQuery }}"
                    </a>
                </template>
            </div>
        </div>
    `
};

// Rendi il componente disponibile globalmente
window.AutocompleteSelect = AutocompleteSelect;

