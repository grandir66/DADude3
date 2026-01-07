// API Utilities - Gestione centralizzata errori e fetch API
// Fornisce wrapper per fetch con gestione errori automatica e toast notifications

/**
 * Wrapper per fetch con gestione errori automatica
 * @param {string} url - URL della richiesta
 * @param {object} options - Opzioni fetch standard
 * @returns {Promise<Response>}
 */
async function apiFetch(url, options = {}) {
    // Mostra loading se non disabilitato esplicitamente
    if (options.showLoading !== false && window.showLoading) {
        window.showLoading(options.loadingText || 'Caricamento...');
    }
    
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        // Nascondi loading
        if (options.showLoading !== false && window.hideLoading) {
            window.hideLoading();
        }
        
        // Gestione errori HTTP
        if (!response.ok) {
            let errorMessage = `Errore ${response.status}`;
            
            try {
                const errorData = await response.json();
                errorMessage = errorData.detail || errorData.message || errorMessage;
            } catch (e) {
                errorMessage = response.statusText || errorMessage;
            }
            
            // Mostra toast errore se disponibile
            if (window.toastError) {
                window.toastError(errorMessage);
            } else {
                console.error('API Error:', errorMessage);
            }
            
            throw new Error(errorMessage);
        }
        
        return response;
    } catch (error) {
        // Nascondi loading in caso di errore
        if (options.showLoading !== false && window.hideLoading) {
            window.hideLoading();
        }
        
        // Gestione errori di rete
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            const networkError = 'Errore di connessione. Verifica la connessione di rete.';
            if (window.toastError) {
                window.toastError(networkError);
            } else {
                console.error('Network Error:', networkError);
            }
            throw new Error(networkError);
        }
        
        throw error;
    }
}

/**
 * GET request helper
 */
async function apiGet(url, options = {}) {
    return apiFetch(url, { ...options, method: 'GET' });
}

/**
 * POST request helper
 */
async function apiPost(url, data, options = {}) {
    return apiFetch(url, {
        ...options,
        method: 'POST',
        body: JSON.stringify(data)
    });
}

/**
 * PUT request helper
 */
async function apiPut(url, data, options = {}) {
    return apiFetch(url, {
        ...options,
        method: 'PUT',
        body: JSON.stringify(data)
    });
}

/**
 * DELETE request helper
 */
async function apiDelete(url, options = {}) {
    return apiFetch(url, { ...options, method: 'DELETE' });
}

/**
 * Helper per ottenere JSON dalla risposta
 */
async function apiJson(url, options = {}) {
    const response = await apiFetch(url, options);
    return response.json();
}

// Esponi funzioni globalmente
window.apiFetch = apiFetch;
window.apiGet = apiGet;
window.apiPost = apiPost;
window.apiPut = apiPut;
window.apiDelete = apiDelete;
window.apiJson = apiJson;

