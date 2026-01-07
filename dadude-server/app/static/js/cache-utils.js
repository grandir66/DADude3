// Cache Utilities - Gestione cache e debouncing per performance

/**
 * Debounce function - ritarda l'esecuzione di una funzione
 * @param {Function} func - Funzione da eseguire
 * @param {number} wait - Tempo di attesa in ms
 * @returns {Function} Funzione debounced
 */
function debounce(func, wait = 300) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Throttle function - limita l'esecuzione di una funzione
 * @param {Function} func - Funzione da eseguire
 * @param {number} limit - Limite di tempo in ms
 * @returns {Function} Funzione throttled
 */
function throttle(func, limit = 300) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

/**
 * Cache manager per risultati API
 */
const ApiCache = {
    cache: new Map(),
    defaultTTL: 5 * 60 * 1000, // 5 minuti
    
    /**
     * Ottiene un valore dalla cache
     * @param {string} key - Chiave cache
     * @returns {any|null} Valore in cache o null
     */
    get(key) {
        const item = this.cache.get(key);
        if (!item) return null;
        
        if (Date.now() > item.expiry) {
            this.cache.delete(key);
            return null;
        }
        
        return item.value;
    },
    
    /**
     * Salva un valore nella cache
     * @param {string} key - Chiave cache
     * @param {any} value - Valore da salvare
     * @param {number} ttl - Time to live in ms (opzionale)
     */
    set(key, value, ttl = this.defaultTTL) {
        this.cache.set(key, {
            value,
            expiry: Date.now() + ttl
        });
    },
    
    /**
     * Rimuove un valore dalla cache
     * @param {string} key - Chiave cache
     */
    delete(key) {
        this.cache.delete(key);
    },
    
    /**
     * Pulisce tutta la cache
     */
    clear() {
        this.cache.clear();
    },
    
    /**
     * Pulisce le entry scadute
     */
    cleanup() {
        const now = Date.now();
        for (const [key, item] of this.cache.entries()) {
            if (now > item.expiry) {
                this.cache.delete(key);
            }
        }
    }
};

// Cleanup automatico ogni 10 minuti
setInterval(() => ApiCache.cleanup(), 10 * 60 * 1000);

/**
 * Fetch con cache
 * @param {string} url - URL da fetchare
 * @param {object} options - Opzioni fetch
 * @param {number} ttl - Time to live cache in ms
 * @returns {Promise<any>} Risultato fetch o cache
 */
async function cachedFetch(url, options = {}, ttl = 5 * 60 * 1000) {
    const cacheKey = `fetch:${url}:${JSON.stringify(options)}`;
    
    // Controlla cache
    const cached = ApiCache.get(cacheKey);
    if (cached) {
        return cached;
    }
    
    // Fetch e salva in cache
    try {
        const response = await fetch(url, options);
        if (response.ok) {
            const data = await response.json();
            ApiCache.set(cacheKey, data, ttl);
            return data;
        }
        throw new Error(`HTTP ${response.status}`);
    } catch (error) {
        console.error('Fetch error:', error);
        throw error;
    }
}

// Esponi funzioni globalmente
window.debounce = debounce;
window.throttle = throttle;
window.ApiCache = ApiCache;
window.cachedFetch = cachedFetch;

