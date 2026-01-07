// DataTable Component per Vue.js 3
// Tabella moderna con ricerca, ordinamento e paginazione

// Rendi disponibile globalmente
window.DataTable = {
    props: {
        data: {
            type: Array,
            required: true,
            default: () => []
        },
        columns: {
            type: Array,
            required: true
        },
        searchable: {
            type: Boolean,
            default: true
        },
        sortable: {
            type: Boolean,
            default: true
        },
        paginated: {
            type: Boolean,
            default: true
        },
        itemsPerPage: {
            type: Number,
            default: 10
        },
        emptyMessage: {
            type: String,
            default: 'Nessun dato disponibile'
        }
    },
    data() {
        return {
            searchQuery: '',
            sortColumn: null,
            sortDirection: 'asc',
            currentPage: 1
        }
    },
    computed: {
        filteredData() {
            let result = [...this.data];
            
            // Applica ricerca
            if (this.searchQuery && this.searchable) {
                const query = this.searchQuery.toLowerCase();
                result = result.filter(row => {
                    return this.columns.some(col => {
                        const value = this.getCellValue(row, col);
                        return value && value.toString().toLowerCase().includes(query);
                    });
                });
            }
            
            // Applica ordinamento
            if (this.sortColumn && this.sortable) {
                result.sort((a, b) => {
                    const aVal = this.getCellValue(a, this.sortColumn);
                    const bVal = this.getCellValue(b, this.sortColumn);
                    
                    // Gestione null/undefined
                    if (aVal == null && bVal == null) return 0;
                    if (aVal == null) return 1;
                    if (bVal == null) return -1;
                    
                    // Confronto numerico o stringa
                    if (typeof aVal === 'number' && typeof bVal === 'number') {
                        return this.sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
                    }
                    
                    const aStr = String(aVal).toLowerCase();
                    const bStr = String(bVal).toLowerCase();
                    
                    if (aStr < bStr) return this.sortDirection === 'asc' ? -1 : 1;
                    if (aStr > bStr) return this.sortDirection === 'asc' ? 1 : -1;
                    return 0;
                });
            }
            
            return result;
        },
        paginatedData() {
            if (!this.paginated) {
                return this.filteredData;
            }
            
            const start = (this.currentPage - 1) * this.itemsPerPage;
            const end = start + this.itemsPerPage;
            return this.filteredData.slice(start, end);
        },
        totalPages() {
            return Math.ceil(this.filteredData.length / this.itemsPerPage);
        },
        hasData() {
            return this.filteredData.length > 0;
        }
    },
    methods: {
        getCellValue(row, column) {
            if (typeof column.field === 'function') {
                return column.field(row);
            }
            return column.field ? this.getNestedValue(row, column.field) : '';
        },
        getNestedValue(obj, path) {
            return path.split('.').reduce((o, p) => o && o[p], obj);
        },
        sort(column) {
            if (!this.sortable || !column.sortable) return;
            
            if (this.sortColumn === column) {
                this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                this.sortColumn = column;
                this.sortDirection = 'asc';
            }
        },
        getSortIcon(column) {
            if (this.sortColumn !== column) {
                return 'bi-arrow-down-up';
            }
            return this.sortDirection === 'asc' ? 'bi-arrow-up' : 'bi-arrow-down';
        },
        goToPage(page) {
            if (page >= 1 && page <= this.totalPages) {
                this.currentPage = page;
            }
        },
        previousPage() {
            if (this.currentPage > 1) {
                this.currentPage--;
            }
        },
        nextPage() {
            if (this.currentPage < this.totalPages) {
                this.currentPage++;
            }
        },
        resetFilters() {
            this.searchQuery = '';
            this.sortColumn = null;
            this.sortDirection = 'asc';
            this.currentPage = 1;
        }
    },
    watch: {
        filteredData() {
            // Reset alla prima pagina quando cambiano i filtri
            this.currentPage = 1;
        }
    },
    template: `
        <div class="data-table-wrapper">
            <!-- Search Bar -->
            <div v-if="searchable" class="mb-3">
                <div class="input-group">
                    <span class="input-group-text">
                        <i class="bi bi-search"></i>
                    </span>
                    <input
                        type="text"
                        class="form-control"
                        v-model="searchQuery"
                        :placeholder="'Cerca tra ' + data.length + ' elementi...'"
                    />
                    <button
                        v-if="searchQuery"
                        class="btn btn-outline-secondary"
                        type="button"
                        @click="resetFilters"
                    >
                        <i class="bi bi-x"></i>
                    </button>
                </div>
                <small v-if="searchQuery" class="text-muted">
                    Trovati {{ filteredData.length }} risultati
                </small>
            </div>
            
            <!-- Table -->
            <div class="table-responsive">
                <table class="table table-hover table-modern mb-0">
                    <thead>
                        <tr>
                            <th
                                v-for="column in columns"
                                :key="column.key || column.field"
                                :class="{ 'sortable': sortable && column.sortable !== false }"
                                @click="sort(column)"
                                :style="sortable && column.sortable !== false ? 'cursor: pointer;' : ''"
                            >
                                <div class="d-flex align-items-center justify-content-between">
                                    <span>{{ column.label }}</span>
                                    <i
                                        v-if="sortable && column.sortable !== false"
                                        :class="['bi', getSortIcon(column)]"
                                    ></i>
                                </div>
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-if="!hasData">
                            <td :colspan="columns.length" class="text-center text-muted py-5">
                                <i class="bi bi-inbox display-4 d-block mb-2"></i>
                                {{ emptyMessage }}
                            </td>
                        </tr>
                        <tr v-for="(row, index) in paginatedData" :key="index">
                            <td v-for="column in columns" :key="column.key || column.field">
                                <slot
                                    :name="'cell-' + (column.key || column.field)"
                                    :row="row"
                                    :value="getCellValue(row, column)"
                                    :column="column"
                                >
                                    <span v-html="getCellValue(row, column)"></span>
                                </slot>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            <div v-if="paginated && totalPages > 1" class="d-flex justify-content-between align-items-center mt-3">
                <div class="text-muted">
                    Mostrando {{ (currentPage - 1) * itemsPerPage + 1 }} - 
                    {{ Math.min(currentPage * itemsPerPage, filteredData.length) }} 
                    di {{ filteredData.length }} risultati
                </div>
                <nav>
                    <ul class="pagination mb-0">
                        <li class="page-item" :class="{ disabled: currentPage === 1 }">
                            <a class="page-link" href="#" @click.prevent="previousPage">
                                <i class="bi bi-chevron-left"></i>
                            </a>
                        </li>
                        <li
                            v-for="page in totalPages"
                            :key="page"
                            class="page-item"
                            :class="{ active: page === currentPage }"
                        >
                            <a
                                class="page-link"
                                href="#"
                                @click.prevent="goToPage(page)"
                            >
                                {{ page }}
                            </a>
                        </li>
                        <li class="page-item" :class="{ disabled: currentPage === totalPages }">
                            <a class="page-link" href="#" @click.prevent="nextPage">
                                <i class="bi bi-chevron-right"></i>
                            </a>
                        </li>
                    </ul>
                </nav>
            </div>
        </div>
    `
};

