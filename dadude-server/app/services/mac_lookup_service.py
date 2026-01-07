"""
MAC Address Vendor Lookup - Servizio per risolvere MAC address usando API online e database locale.
"""
import requests
import time
from typing import Dict, Any, Optional, List
from loguru import logger
from concurrent.futures import ThreadPoolExecutor, as_completed
from .vendor_database import lookup_vendor_local, get_device_type_from_vendor, get_os_from_vendor


class MACLookupService:
    """Servizio per risolvere MAC address usando API online."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # API endpoints disponibili (in ordine di priorità)
        # Usiamo più fonti per massimizzare il riconoscimento
        self.apis = [
            {
                'name': 'macvendors',
                'url': 'https://api.macvendors.com/{mac}',
                'rate_limit': 1.0,  # 1 richiesta al secondo
                'enabled': True
            },
            {
                'name': 'macaddress.io',
                'url': 'https://api.macaddress.io/v1',
                'api_key': self.config.get('mac_lookup', {}).get('api_key'),
                'rate_limit': 0.5,  # 2 richieste al secondo
                'enabled': True
            },
            {
                'name': 'maclookup',
                'url': 'https://api.maclookup.app/v2/macs/{mac}',
                'rate_limit': 0.5,  # 2 richieste al secondo
                'enabled': True
            },
            {
                'name': 'macvendorlookup',
                'url': 'https://macvendorlookup.com/api/v2/{mac}',
                'rate_limit': 1.0,  # 1 richiesta al secondo
                'enabled': True
            },
            {
                'name': 'macvendorsco',
                'url': 'https://macvendors.co/api/vendordetails/{mac}',
                'rate_limit': 1.0,
                'enabled': True
            },
            {
                'name': 'macaddresses',
                'url': 'https://macaddresses.macvendors.com/api/v1/{mac}',
                'rate_limit': 1.0,
                'enabled': True
            }
        ]
        
        self.last_request_time = {}
        self.cache = {}  # Cache locale per evitare richieste duplicate
    
    def lookup(self, mac_address: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """
        Cerca informazioni su un MAC address.
        Prima controlla il database locale, poi usa le API online.
        
        Args:
            mac_address: MAC address in formato XX:XX:XX:XX:XX:XX o XXXXXXXXXXXX
            use_cache: Usa cache locale se True
            
        Returns:
            Dizionario con vendor e altre info, o None se non trovato
        """
        # Normalizza MAC address
        mac = self._normalize_mac(mac_address)
        if not mac:
            return None
        
        # Controlla cache
        if use_cache and mac in self.cache:
            return self.cache[mac]
        
        # Prima prova il database locale (veloce e offline) con matching migliorato
        try:
            # Prova lookup con MAC normalizzato
            local_result = lookup_vendor_local(mac)
            
            # Se non trovato, prova anche con varianti del formato
            if not local_result:
                # Prova senza normalizzazione (caso originale)
                local_result = lookup_vendor_local(mac_address)
            
            if local_result:
                # Mappa 'type' a 'category' se necessario
                device_type = local_result.get('type', 'unknown')
                category = device_type  # Usa type come category di default
                
                # Mapping più preciso per category
                if device_type in ['server', 'workstation', 'storage']:
                    category = device_type
                elif device_type in ['router', 'switch', 'firewall', 'ap']:
                    category = 'network'
                elif device_type == 'printer':
                    category = 'printer'
                elif device_type == 'ipcamera':
                    category = 'camera'
                
                result = {
                    'vendor': local_result.get('vendor'),
                    'device_type': device_type,
                    'category': category,
                    'os_family': local_result.get('os', 'unknown'),
                    'source': 'local_database'
                }
                self.cache[mac] = result
                logger.info(f"Found {mac} in local database: {result['vendor']} ({device_type})")
                return result
            else:
                logger.debug(f"No local match for MAC {mac}")
        except Exception as e:
            logger.warning(f"Local vendor lookup error for {mac}: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            pass
        
        # Poi prova le API online in parallelo per massimizzare il riconoscimento
        # Usa ThreadPoolExecutor per query parallele
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        enabled_apis = [api for api in self.apis if api.get('enabled', True)]
        if enabled_apis:
            with ThreadPoolExecutor(max_workers=min(len(enabled_apis), 4)) as executor:
                future_to_api = {
                    executor.submit(self._query_api, api, mac): api
                    for api in enabled_apis
                }
                
                results = []
                for future in as_completed(future_to_api):
                    api = future_to_api[future]
                    try:
                        result = future.result()
                        if result and result.get('vendor'):
                            results.append((api['name'], result))
                    except Exception as e:
                        logger.debug(f"API {api['name']} failed for {mac}: {e}")
                
                # Prendi il primo risultato valido o combina i risultati
                if results:
                    # Preferisci risultati con più informazioni
                    best_result = max(results, key=lambda x: len(str(x[1])))
                    api_name, result = best_result
                    
                    # Arricchisci con inferenze sul tipo
                    vendor = result.get('vendor', '')
                    if 'device_type' not in result or result.get('device_type') == 'unknown':
                        result['device_type'] = get_device_type_from_vendor(vendor)
                        result['category'] = result['device_type']
                    if 'os_family' not in result or result.get('os_family') == 'unknown':
                        result['os_family'] = get_os_from_vendor(vendor)
                    
                    # Combina informazioni da più fonti se disponibili
                    if len(results) > 1:
                        result['sources'] = [name for name, _ in results]
                        result['source'] = f"multiple_apis ({', '.join(result['sources'])})"
                    else:
                        result['source'] = api_name
                    
                    self.cache[mac] = result
                    logger.info(f"Found {mac} via API {api_name}: {vendor}")
                    return result
        
        logger.debug(f"No vendor found for MAC {mac} in any source")
        return None
    
    def lookup_batch(self, mac_addresses: list, max_workers: int = 5) -> Dict[str, Dict[str, Any]]:
        """
        Cerca informazioni su più MAC address in parallelo.
        
        Args:
            mac_addresses: Lista di MAC address
            max_workers: Numero massimo di worker paralleli
            
        Returns:
            Dizionario {mac: result}
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_mac = {
                executor.submit(self.lookup, mac): mac
                for mac in mac_addresses
            }
            
            for future in as_completed(future_to_mac):
                mac = future_to_mac[future]
                try:
                    result = future.result()
                    if result:
                        results[mac] = result
                except Exception as e:
                    logger.debug(f"Error looking up {mac}: {e}")
        
        return results
    
    def _query_api(self, api: Dict[str, Any], mac: str) -> Optional[Dict[str, Any]]:
        """Esegue una query a una specifica API, provando anche varianti del formato MAC per migliorare il matching."""
        api_name = api['name']
        
        # Rate limiting
        if api_name in self.last_request_time:
            elapsed = time.time() - self.last_request_time[api_name]
            if elapsed < api.get('rate_limit', 1.0):
                time.sleep(api['rate_limit'] - elapsed)
        
        self.last_request_time[api_name] = time.time()
        
        # Genera varianti del MAC per migliorare il matching (alcune API preferiscono formati diversi)
        mac_variants = [
            mac,  # Formato standard XX:XX:XX:XX:XX:XX
            mac.replace(':', '-'),  # XX-XX-XX-XX-XX-XX
            mac.replace(':', ''),  # XXXXXXXXXXXX
        ]
        
        # Prova ogni variante finché non trova un risultato valido
        for mac_var in mac_variants:
            try:
                if api_name == 'macvendors':
                    result = self._query_macvendors(api['url'].format(mac=mac_var))
                elif api_name == 'macaddress.io':
                    result = self._query_macaddress_io(api['url'], mac_var, api.get('api_key'))
                elif api_name == 'maclookup':
                    result = self._query_maclookup(api['url'].format(mac=mac_var))
                elif api_name == 'macvendorlookup':
                    result = self._query_macvendorlookup(api['url'].format(mac=mac_var))
                elif api_name == 'macvendorsco':
                    result = self._query_macvendorsco(api['url'].format(mac=mac_var))
                elif api_name == 'macaddresses':
                    result = self._query_macaddresses(api['url'].format(mac=mac_var))
                else:
                    result = None
                
                # Se trovato un risultato valido, restituiscilo
                if result and result.get('vendor') and result.get('vendor').strip():
                    return result
            except Exception as e:
                logger.debug(f"API {api_name} variant {mac_var} failed: {e}")
                continue
        
        return None
    
    def _query_macvendors(self, url: str) -> Optional[Dict[str, Any]]:
        """Query a macvendors.com (gratuito, no API key)."""
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                vendor = response.text.strip()
                if vendor and not vendor.startswith('Not Found'):
                    return {
                        'vendor': vendor,
                        'source': 'macvendors.com'
                    }
        except Exception as e:
            logger.debug(f"macvendors.com error: {e}")
        
        return None
    
    def _query_macaddress_io(self, url: str, mac: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Query a macaddress.io (richiede API key per uso intensivo)."""
        if not api_key:
            # Prova comunque senza API key (limitato)
            return None
        
        try:
            params = {
                'output': 'json',
                'search': mac
            }
            headers = {'X-Authentication-Token': api_key} if api_key else {}
            
            response = requests.get(url, params=params, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('vendorDetails'):
                    vendor_info = data['vendorDetails']
                    return {
                        'vendor': vendor_info.get('companyName', ''),
                        'country': vendor_info.get('countryCode', ''),
                        'address': vendor_info.get('companyAddress', ''),
                        'source': 'macaddress.io'
                    }
        except Exception as e:
            logger.debug(f"macaddress.io error: {e}")
        
        return None
    
    def _normalize_mac(self, mac: str) -> Optional[str]:
        """
        Normalizza un MAC address al formato standard XX:XX:XX:XX:XX:XX.
        
        Args:
            mac: MAC address in vari formati
            
        Returns:
            MAC address normalizzato o None se invalido
        """
        if not mac:
            return None
        
        # Rimuovi spazi e converti in maiuscolo
        mac_clean = mac.replace(' ', '').replace('-', '').replace(':', '').replace('.', '').upper()
        
        # Verifica formato (12 caratteri esadecimali)
        if len(mac_clean) != 12:
            logger.debug(f"Invalid MAC length: {mac} -> {mac_clean} (length: {len(mac_clean)})")
            return None
        
        try:
            int(mac_clean, 16)  # Verifica che sia esadecimale
        except ValueError:
            logger.debug(f"Invalid MAC format (not hex): {mac}")
            return None
        
        # Formatta come XX:XX:XX:XX:XX:XX
        normalized = ':'.join([mac_clean[i:i+2] for i in range(0, 12, 2)])
        logger.debug(f"Normalized MAC: {mac} -> {normalized}")
        return normalized
    
    def _query_maclookup(self, url: str) -> Optional[Dict[str, Any]]:
        """Query a maclookup.app (gratuito, no API key)."""
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('found'):
                    return {
                        'vendor': data.get('company', ''),
                        'country': data.get('country', ''),
                        'address': data.get('address', ''),
                        'source': 'maclookup.app'
                    }
        except Exception as e:
            logger.debug(f"maclookup.app error: {e}")
        
        return None
    
    def _query_macvendorlookup(self, url: str) -> Optional[Dict[str, Any]]:
        """Query a macvendorlookup.com (gratuito, no API key)."""
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('vendor'):
                    return {
                        'vendor': data.get('vendor', ''),
                        'country': data.get('country', ''),
                        'source': 'macvendorlookup.com'
                    }
        except Exception as e:
            logger.debug(f"macvendorlookup.com error: {e}")
        
        return None
    
    def _query_macvendorsco(self, url: str) -> Optional[Dict[str, Any]]:
        """Query a macvendors.co (gratuito, no API key)."""
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('vendor'):
                    return {
                        'vendor': data.get('vendor', ''),
                        'country': data.get('country', ''),
                        'address': data.get('address', ''),
                        'source': 'macvendors.co'
                    }
        except Exception as e:
            logger.debug(f"macvendors.co error: {e}")
        
        return None
    
    def _query_macaddresses(self, url: str) -> Optional[Dict[str, Any]]:
        """Query a macaddresses.macvendors.com (gratuito, no API key)."""
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('vendor'):
                    return {
                        'vendor': data.get('vendor', ''),
                        'country': data.get('country', ''),
                        'source': 'macaddresses.macvendors.com'
                    }
        except Exception as e:
            logger.debug(f"macaddresses.macvendors.com error: {e}")
        
        return None


# Singleton
_mac_lookup_service: Optional[MACLookupService] = None


def get_mac_lookup_service() -> MACLookupService:
    global _mac_lookup_service
    if _mac_lookup_service is None:
        _mac_lookup_service = MACLookupService()
    return _mac_lookup_service

