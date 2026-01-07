"""
DaDude - Device Merge Service
Servizio per deduplicazione intelligente e merge di device
"""
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from loguru import logger
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from ..models.inventory import InventoryDevice
from ..models.database import DiscoveredDevice


class DeviceMergeService:
    """Servizio per gestire merge intelligente di device"""
    
    # Campi usati per calcolare score di completezza
    COMPLETENESS_FIELDS = [
        'name', 'hostname', 'manufacturer', 'model', 'os_family', 
        'os_version', 'serial_number', 'cpu_cores', 'ram_total_gb', 'open_ports'
    ]
    
    def find_duplicates(
        self, 
        discovered_device: DiscoveredDevice, 
        customer_id: str, 
        session: Session
    ) -> List[InventoryDevice]:
        """
        Trova device esistenti potenzialmente duplicati.
        Usa MAC come primary key, IP e hostname come fallback.
        
        Args:
            discovered_device: Device scoperto
            customer_id: ID del cliente
            session: Sessione database
            
        Returns:
            Lista di device esistenti potenzialmente duplicati
        """
        # Criteri di matching (in ordine di priorità)
        conditions = []
        
        # Primary: MAC address
        if discovered_device.mac_address:
            mac_condition = and_(
                InventoryDevice.customer_id == customer_id,
                InventoryDevice.active == True,
                InventoryDevice.mac_address == discovered_device.mac_address
            )
            conditions.append(mac_condition)
        
        # Fallback 1: Primary IP
        if discovered_device.address:
            ip_condition = and_(
                InventoryDevice.customer_id == customer_id,
                InventoryDevice.active == True,
                InventoryDevice.primary_ip == discovered_device.address
            )
            conditions.append(ip_condition)
        
        # Fallback 2: Hostname (se presente e non null)
        if discovered_device.hostname:
            hostname_condition = and_(
                InventoryDevice.customer_id == customer_id,
                InventoryDevice.active == True,
                InventoryDevice.hostname == discovered_device.hostname
            )
            conditions.append(hostname_condition)
        
        if not conditions:
            return []
        
        # Cerca device che corrispondono a qualsiasi condizione
        query = session.query(InventoryDevice).filter(or_(*conditions))
        duplicates = query.all()
        
        # Rimuovi duplicati (se stesso device matcha più condizioni)
        seen_ids = set()
        unique_duplicates = []
        for dup in duplicates:
            if dup.id not in seen_ids:
                seen_ids.add(dup.id)
                unique_duplicates.append(dup)
        
        return unique_duplicates
    
    def compare_devices(
        self, 
        existing: InventoryDevice, 
        discovered: DiscoveredDevice
    ) -> Dict[str, Any]:
        """
        Confronta due device e restituisce differenze dettagliate.
        
        Args:
            existing: Device esistente nell'inventory
            discovered: Device scoperto nella scansione
            
        Returns:
            Dizionario con differenze e confronti
        """
        differences = {
            'matching_fields': [],
            'conflicting_fields': [],
            'new_fields': [],
            'existing_only_fields': []
        }
        
        # Mappa campi tra DiscoveredDevice e InventoryDevice
        field_mapping = {
            'hostname': ('hostname', 'hostname'),
            'vendor': ('manufacturer', 'vendor'),
            'model': ('model', 'model'),
            'device_type': ('device_type', 'device_type'),
            'category': ('category', 'category'),
            'os_family': ('os_family', 'os_family'),
            'os_version': ('os_version', 'os_version'),
            'serial_number': ('serial_number', 'serial_number'),
            'cpu_cores': ('cpu_cores', 'cpu_cores'),
            'ram_total_mb': ('ram_total_gb', 'ram_total_mb'),  # Conversione MB -> GB
            'open_ports': ('open_ports', 'open_ports'),
        }
        
        for existing_field, (existing_attr, discovered_attr) in field_mapping.items():
            existing_value = getattr(existing, existing_attr, None)
            discovered_value = getattr(discovered, discovered_attr, None)
            
            # Conversione ram_total_mb -> ram_total_gb
            if existing_field == 'ram_total_mb' and discovered_value:
                discovered_value = discovered_value / 1024.0  # MB to GB
            
            if existing_value and discovered_value:
                if existing_value != discovered_value:
                    differences['conflicting_fields'].append({
                        'field': existing_field,
                        'existing': existing_value,
                        'discovered': discovered_value
                    })
                else:
                    differences['matching_fields'].append(existing_field)
            elif discovered_value and not existing_value:
                differences['new_fields'].append({
                    'field': existing_field,
                    'value': discovered_value
                })
            elif existing_value and not discovered_value:
                differences['existing_only_fields'].append({
                    'field': existing_field,
                    'value': existing_value
                })
        
        return differences
    
    def calculate_completeness_score(self, device: Any) -> float:
        """
        Calcola score di completezza dati.
        Conta campi non-null tra quelli importanti.
        
        Args:
            device: Device (InventoryDevice o DiscoveredDevice)
            
        Returns:
            Score da 0.0 a 1.0
        """
        non_null_count = 0
        total_fields = len(self.COMPLETENESS_FIELDS)
        
        for field in self.COMPLETENESS_FIELDS:
            value = getattr(device, field, None)
            
            # Gestione speciale per open_ports (lista/array)
            if field == 'open_ports':
                if value and isinstance(value, (list, dict)) and len(value) > 0:
                    non_null_count += 1
            elif value is not None and value != '':
                non_null_count += 1
        
        return non_null_count / total_fields if total_fields > 0 else 0.0
    
    def propose_merge(
        self, 
        existing: InventoryDevice, 
        discovered: DiscoveredDevice
    ) -> Dict[str, Any]:
        """
        Propone merge con raccomandazioni.
        
        Args:
            existing: Device esistente
            discovered: Device scoperto
            
        Returns:
            Dizionario con proposta merge e raccomandazione
        """
        differences = self.compare_devices(existing, discovered)
        existing_score = self.calculate_completeness_score(existing)
        discovered_score = self.calculate_completeness_score(discovered)
        
        # Determina raccomandazione
        recommendation = 'skip'  # Default: mantieni esistente
        
        if discovered_score > existing_score + 0.1:  # Nuovo è significativamente migliore
            recommendation = 'overwrite'
        elif discovered_score > existing_score:
            recommendation = 'merge'  # Nuovo leggermente migliore, combina
        elif len(differences['new_fields']) > len(differences['conflicting_fields']):
            recommendation = 'merge'  # Più nuovi campi che conflitti
        elif len(differences['conflicting_fields']) == 0:
            recommendation = 'merge'  # Nessun conflitto, solo nuovi campi
        
        return {
            'existing_device_id': existing.id,
            'existing_score': existing_score,
            'discovered_score': discovered_score,
            'differences': differences,
            'recommendation': recommendation,
            'confidence': abs(existing_score - discovered_score)  # Maggiore differenza = maggiore confidenza
        }
    
    def merge_devices(
        self,
        existing: InventoryDevice,
        discovered: DiscoveredDevice,
        merge_strategy: str,
        session: Session
    ) -> InventoryDevice:
        """
        Esegue merge secondo strategia.
        
        Args:
            existing: Device esistente da aggiornare
            discovered: Device scoperto con nuovi dati
            merge_strategy: 'merge', 'overwrite', o 'skip'
            session: Sessione database
            
        Returns:
            Device esistente aggiornato
        """
        if merge_strategy == 'skip':
            # Mantiene esistente, ignora nuovo
            logger.info(f"Skipping merge for device {existing.id} (strategy: skip)")
            return existing
        
        elif merge_strategy == 'overwrite':
            # Sostituisce esistente con nuovo
            logger.info(f"Overwriting device {existing.id} with discovered data")
            self._apply_discovered_data(existing, discovered, overwrite=True)
        
        elif merge_strategy == 'merge':
            # Combina dati da entrambe le versioni (preferisce valori non-null)
            logger.info(f"Merging data into device {existing.id}")
            self._apply_discovered_data(existing, discovered, overwrite=False)
        
        else:
            raise ValueError(f"Unknown merge strategy: {merge_strategy}")
        
        # Aggiorna tracking
        now = datetime.utcnow()
        if not existing.first_seen_at:
            existing.first_seen_at = now
        existing.last_verified_at = now
        existing.verification_count = (existing.verification_count or 0) + 1
        
        session.add(existing)
        return existing
    
    def _apply_discovered_data(
        self, 
        existing: InventoryDevice, 
        discovered: DiscoveredDevice, 
        overwrite: bool = False
    ):
        """Applica dati dal device scoperto a quello esistente"""
        
        # Mappa campi
        field_mapping = {
            'hostname': ('hostname', 'hostname'),
            'vendor': ('manufacturer', 'vendor'),
            'model': ('model', 'model'),
            'device_type': ('device_type', 'device_type'),
            'category': ('category', 'category'),
            'os_family': ('os_family', 'os_family'),
            'os_version': ('os_version', 'os_version'),
            'serial_number': ('serial_number', 'serial_number'),
            'cpu_cores': ('cpu_cores', 'cpu_cores'),
            'open_ports': ('open_ports', 'open_ports'),
        }
        
        for existing_field, (existing_attr, discovered_attr) in field_mapping.items():
            existing_value = getattr(existing, existing_attr, None)
            discovered_value = getattr(discovered, discovered_attr, None)
            
            # Gestione speciale per ram_total_mb -> ram_total_gb
            if existing_field == 'ram_total_mb':
                if discovered.ram_total_mb:
                    discovered_value = discovered.ram_total_mb / 1024.0  # MB to GB
                    existing_attr = 'ram_total_gb'
            
            if overwrite:
                # Sostituisci sempre
                if discovered_value is not None:
                    setattr(existing, existing_attr, discovered_value)
            else:
                # Merge: preferisci valori non-null, ma non sovrascrivere se esistente ha valore
                if discovered_value is not None:
                    if existing_value is None or existing_value == '':
                        setattr(existing, existing_attr, discovered_value)
                    elif existing_field == 'open_ports' and isinstance(existing_value, list) and isinstance(discovered_value, list):
                        # Unisci porte aperte, evitando duplicati
                        existing_ports = {(p.get('port'), p.get('protocol')) for p in existing_value}
                        new_ports = [p for p in discovered_value if (p.get('port'), p.get('protocol')) not in existing_ports]
                        if new_ports:
                            setattr(existing, existing_attr, existing_value + new_ports)
        
        # Aggiorna MAC se non presente
        if discovered.mac_address and not existing.mac_address:
            existing.mac_address = discovered.mac_address
            existing.primary_mac = discovered.mac_address
        
        # Aggiorna IP se non presente
        if discovered.address and not existing.primary_ip:
            existing.primary_ip = discovered.address


# Singleton
_merge_service: Optional[DeviceMergeService] = None


def get_device_merge_service() -> DeviceMergeService:
    """Ottiene istanza singleton del servizio merge"""
    global _merge_service
    if _merge_service is None:
        _merge_service = DeviceMergeService()
    return _merge_service
