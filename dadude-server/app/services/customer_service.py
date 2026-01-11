"""
DaDude - Customer Service
Gestione clienti, reti, credenziali e assegnazioni device
"""
import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime
from loguru import logger
from sqlalchemy.orm import Session
from sqlalchemy import or_

from ..models.database import (
    Customer as CustomerDB,
    Network as NetworkDB,
    Credential as CredentialDB,
    CustomerCredentialLink as CredentialLinkDB,
    DeviceAssignment as DeviceAssignmentDB,
    AgentAssignment as AgentAssignmentDB,
    init_db, get_session
)
from ..models.customer_schemas import (
    CustomerCreate, CustomerUpdate, Customer,
    NetworkCreate, NetworkUpdate, Network,
    CredentialCreate, CredentialUpdate, Credential, CredentialSafe,
    DeviceAssignmentCreate, DeviceAssignmentUpdate, DeviceAssignment,
    AgentAssignmentCreate, AgentAssignmentUpdate, AgentAssignment, AgentAssignmentSafe,
)
from ..config import get_settings
from .encryption_service import get_encryption_service


class CustomerService:
    """Servizio per gestione multi-tenant"""
    
    def __init__(self):
        settings = get_settings()
        # Usa database sincrono
        db_url = settings.database_url
        self._engine = init_db(db_url)
        logger.info("CustomerService initialized with database")
    
    def _get_session(self) -> Session:
        """Ottiene sessione database"""
        return get_session(self._engine)
    
    # ==========================================
    # CUSTOMERS
    # ==========================================
    
    def create_customer(self, data: CustomerCreate) -> Customer:
        """Crea nuovo cliente"""
        session = self._get_session()
        try:
            # Verifica codice univoco
            existing = session.query(CustomerDB).filter(
                CustomerDB.code == data.code.upper()
            ).first()
            if existing:
                raise ValueError(f"Cliente con codice {data.code} già esistente")
            
            customer = CustomerDB(
                code=data.code.upper(),
                name=data.name,
                description=data.description,
                contact_name=data.contact_name,
                contact_email=data.contact_email,
                contact_phone=data.contact_phone,
                address=data.address,
                notes=data.notes,
                active=data.active,
            )
            session.add(customer)
            session.commit()
            session.refresh(customer)
            
            logger.info(f"Created customer: {customer.code} - {customer.name}")
            return Customer.model_validate(customer)
            
        finally:
            session.close()
    
    def get_customer(self, customer_id: str) -> Optional[Customer]:
        """Ottiene cliente per ID"""
        session = self._get_session()
        try:
            customer = session.query(CustomerDB).filter(
                CustomerDB.id == customer_id
            ).first()
            return Customer.model_validate(customer) if customer else None
        finally:
            session.close()
    
    def get_customer_by_code(self, code: str) -> Optional[Customer]:
        """Ottiene cliente per codice"""
        session = self._get_session()
        try:
            customer = session.query(CustomerDB).filter(
                CustomerDB.code == code.upper()
            ).first()
            return Customer.model_validate(customer) if customer else None
        finally:
            session.close()
    
    def list_customers(
        self,
        active_only: bool = True,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Customer]:
        """Lista clienti con filtri"""
        session = self._get_session()
        try:
            query = session.query(CustomerDB)
            
            if active_only:
                query = query.filter(CustomerDB.active == True)
            
            if search:
                search_pattern = f"%{search}%"
                query = query.filter(or_(
                    CustomerDB.code.ilike(search_pattern),
                    CustomerDB.name.ilike(search_pattern),
                ))
            
            query = query.order_by(CustomerDB.name)
            query = query.offset(offset).limit(limit)
            
            return [Customer.model_validate(c) for c in query.all()]
            
        finally:
            session.close()
    
    def update_customer(self, customer_id: str, data: CustomerUpdate) -> Optional[Customer]:
        """Aggiorna cliente"""
        session = self._get_session()
        try:
            customer = session.query(CustomerDB).filter(
                CustomerDB.id == customer_id
            ).first()
            
            if not customer:
                return None
            
            update_data = data.model_dump(exclude_unset=True)
            for key, value in update_data.items():
                setattr(customer, key, value)
            
            session.commit()
            session.refresh(customer)
            
            logger.info(f"Updated customer: {customer.code}")
            return Customer.model_validate(customer)
            
        finally:
            session.close()
    
    def delete_customer(self, customer_id: str) -> bool:
        """Elimina cliente (soft delete)"""
        session = self._get_session()
        try:
            customer = session.query(CustomerDB).filter(
                CustomerDB.id == customer_id
            ).first()
            
            if not customer:
                return False
            
            customer.active = False
            session.commit()
            
            logger.info(f"Deactivated customer: {customer.code}")
            return True
            
        finally:
            session.close()
    
    # ==========================================
    # NETWORKS
    # ==========================================
    
    def create_network(self, data: NetworkCreate) -> Network:
        """Crea nuova rete per cliente"""
        session = self._get_session()
        try:
            network = NetworkDB(
                customer_id=data.customer_id,
                name=data.name,
                network_type=data.network_type.value,
                ip_network=data.ip_network,
                gateway=data.gateway,
                vlan_id=data.vlan_id,
                vlan_name=data.vlan_name,
                dns_primary=data.dns_primary,
                dns_secondary=data.dns_secondary,
                dhcp_start=data.dhcp_start,
                dhcp_end=data.dhcp_end,
                description=data.description,
                notes=data.notes,
                active=data.active,
            )
            session.add(network)
            session.commit()
            session.refresh(network)
            
            logger.info(f"Created network: {network.name} ({network.ip_network})")
            return Network.model_validate(network)
            
        finally:
            session.close()
    
    def get_network(self, network_id: str) -> Optional[Network]:
        """Ottiene rete per ID"""
        session = self._get_session()
        try:
            network = session.query(NetworkDB).filter(
                NetworkDB.id == network_id
            ).first()
            return Network.model_validate(network) if network else None
        finally:
            session.close()
    
    def list_networks(
        self,
        customer_id: Optional[str] = None,
        network_type: Optional[str] = None,
        vlan_id: Optional[int] = None,
        active_only: bool = True,
    ) -> List[Network]:
        """Lista reti con filtri"""
        session = self._get_session()
        try:
            query = session.query(NetworkDB)
            
            if customer_id:
                query = query.filter(NetworkDB.customer_id == customer_id)
            if network_type:
                query = query.filter(NetworkDB.network_type == network_type)
            if vlan_id:
                query = query.filter(NetworkDB.vlan_id == vlan_id)
            if active_only:
                query = query.filter(NetworkDB.active == True)
            
            return [Network.model_validate(n) for n in query.all()]
            
        finally:
            session.close()
    
    def update_network(self, network_id: str, data: NetworkUpdate) -> Optional[Network]:
        """Aggiorna rete"""
        session = self._get_session()
        try:
            network = session.query(NetworkDB).filter(
                NetworkDB.id == network_id
            ).first()
            
            if not network:
                return None
            
            update_data = data.model_dump(exclude_unset=True)
            for key, value in update_data.items():
                if key == "network_type" and value:
                    value = value.value
                setattr(network, key, value)
            
            session.commit()
            session.refresh(network)
            
            return Network.model_validate(network)
            
        finally:
            session.close()
    
    def delete_network(self, network_id: str) -> bool:
        """Elimina rete"""
        session = self._get_session()
        try:
            network = session.query(NetworkDB).filter(
                NetworkDB.id == network_id
            ).first()
            
            if not network:
                return False
            
            session.delete(network)
            session.commit()
            return True
            
        finally:
            session.close()
    
    # ==========================================
    # CREDENTIALS
    # ==========================================
    
    def create_credential(self, data: CredentialCreate) -> CredentialSafe:
        """Crea nuove credenziali con encryption"""
        session = self._get_session()
        encryption = get_encryption_service()
        try:
            credential = CredentialDB(
                customer_id=data.customer_id if not data.is_global else None,
                is_global=data.is_global,
                name=data.name,
                credential_type=data.credential_type.value,
                username=data.username,
                password=encryption.encrypt(data.password) if data.password else None,
                # SSH
                ssh_port=data.ssh_port,
                ssh_private_key=encryption.encrypt(data.ssh_private_key) if data.ssh_private_key else None,
                ssh_passphrase=encryption.encrypt(data.ssh_passphrase) if data.ssh_passphrase else None,
                ssh_key_type=data.ssh_key_type,
                # SNMP
                snmp_community=data.snmp_community,
                snmp_version=data.snmp_version,
                snmp_port=data.snmp_port,
                snmp_security_level=data.snmp_security_level,
                snmp_auth_protocol=data.snmp_auth_protocol,
                snmp_priv_protocol=data.snmp_priv_protocol,
                snmp_auth_password=encryption.encrypt(data.snmp_auth_password) if data.snmp_auth_password else None,
                snmp_priv_password=encryption.encrypt(data.snmp_priv_password) if data.snmp_priv_password else None,
                # WMI
                wmi_domain=data.wmi_domain,
                wmi_namespace=data.wmi_namespace,
                # MikroTik
                mikrotik_api_port=data.mikrotik_api_port,
                mikrotik_api_ssl=data.mikrotik_api_ssl,
                # API
                api_key=encryption.encrypt(data.api_key) if data.api_key else None,
                api_secret=encryption.encrypt(data.api_secret) if data.api_secret else None,
                api_endpoint=data.api_endpoint,
                # VPN
                vpn_type=data.vpn_type,
                vpn_config=data.vpn_config,
                # Common
                is_default=data.is_default,
                device_filter=data.device_filter,
                description=data.description,
                notes=data.notes,
                active=data.active,
            )
            session.add(credential)
            session.commit()
            session.refresh(credential)
            
            logger.info(f"Created credential: {credential.name}")
            return self._to_credential_safe(credential)
            
        finally:
            session.close()
    
    def _to_credential_safe(self, cred: CredentialDB) -> CredentialSafe:
        """Converte credenziale DB in versione safe (senza password)"""
        return CredentialSafe(
            id=cred.id,
            customer_id=cred.customer_id,
            is_global=cred.is_global or False,
            name=cred.name,
            credential_type=cred.credential_type,
            username=cred.username,
            # SSH
            ssh_port=cred.ssh_port,
            ssh_key_type=cred.ssh_key_type,
            # SNMP
            snmp_community=cred.snmp_community,
            snmp_version=cred.snmp_version,
            snmp_port=cred.snmp_port,
            snmp_security_level=cred.snmp_security_level,
            snmp_auth_protocol=cred.snmp_auth_protocol,
            snmp_priv_protocol=cred.snmp_priv_protocol,
            # WMI
            wmi_domain=cred.wmi_domain,
            wmi_namespace=cred.wmi_namespace,
            # MikroTik
            mikrotik_api_port=cred.mikrotik_api_port,
            mikrotik_api_ssl=cred.mikrotik_api_ssl,
            # API
            api_endpoint=cred.api_endpoint,
            # VPN
            vpn_type=cred.vpn_type,
            # Common
            is_default=cred.is_default,
            device_filter=cred.device_filter,
            description=cred.description,
            notes=cred.notes,
            active=cred.active,
            # Flags for secrets
            has_password=bool(cred.password),
            has_ssh_key=bool(cred.ssh_private_key),
            has_api_key=bool(cred.api_key),
            has_vpn_config=bool(cred.vpn_config),
            created_at=cred.created_at,
            updated_at=cred.updated_at,
        )
    
    def get_credential(self, credential_id: str, include_secrets: bool = False) -> Optional[Any]:
        """Ottiene credenziali per ID"""
        session = self._get_session()
        try:
            cred = session.query(CredentialDB).filter(
                CredentialDB.id == credential_id
            ).first()
            
            if not cred:
                return None
            
            if include_secrets:
                return self._decrypt_credential(cred)
            return self._to_credential_safe(cred)
            
        finally:
            session.close()
    
    def _decrypt_credential(self, cred: CredentialDB) -> Credential:
        """Decripta una credenziale per uso interno"""
        encryption = get_encryption_service()
        
        # Decripta password con gestione errori
        password = None
        if cred.password:
            try:
                password = encryption.decrypt(cred.password)
                logger.debug(f"Successfully decrypted password for credential '{cred.name}' (ID: {cred.id})")
            except Exception as e:
                logger.error(f"Failed to decrypt password for credential '{cred.name}' (ID: {cred.id}): {e}")
                # Prova come plaintext se il decrypt fallisce (per compatibilità con credenziali legacy)
                try:
                    # Se la password non inizia con il prefisso di encryption, potrebbe essere già plaintext
                    if not cred.password.startswith("encrypted:"):
                        password = cred.password
                        logger.warning(f"Using password as plaintext for credential '{cred.name}' (decrypt failed)")
                except:
                    password = None
        
        return Credential(
            id=cred.id,
            customer_id=cred.customer_id,
            is_global=cred.is_global or False,
            name=cred.name,
            credential_type=cred.credential_type,
            username=cred.username,
            password=password,
            # SSH
            ssh_port=cred.ssh_port,
            ssh_private_key=encryption.decrypt(cred.ssh_private_key) if cred.ssh_private_key else None,
            ssh_passphrase=encryption.decrypt(cred.ssh_passphrase) if cred.ssh_passphrase else None,
            ssh_key_type=cred.ssh_key_type,
            # SNMP
            snmp_community=cred.snmp_community,
            snmp_version=cred.snmp_version,
            snmp_port=cred.snmp_port,
            snmp_security_level=cred.snmp_security_level,
            snmp_auth_protocol=cred.snmp_auth_protocol,
            snmp_priv_protocol=cred.snmp_priv_protocol,
            snmp_auth_password=encryption.decrypt(cred.snmp_auth_password) if cred.snmp_auth_password else None,
            snmp_priv_password=encryption.decrypt(cred.snmp_priv_password) if cred.snmp_priv_password else None,
            # WMI
            wmi_domain=cred.wmi_domain,
            wmi_namespace=cred.wmi_namespace,
            # MikroTik
            mikrotik_api_port=cred.mikrotik_api_port,
            mikrotik_api_ssl=cred.mikrotik_api_ssl,
            # API
            api_key=encryption.decrypt(cred.api_key) if cred.api_key else None,
            api_secret=encryption.decrypt(cred.api_secret) if cred.api_secret else None,
            api_endpoint=cred.api_endpoint,
            # VPN
            vpn_type=cred.vpn_type,
            vpn_config=cred.vpn_config,
            # Common
            is_default=cred.is_default,
            device_filter=cred.device_filter,
            description=cred.description,
            notes=cred.notes,
            active=cred.active,
            created_at=cred.created_at,
            updated_at=cred.updated_at,
        )
    
    def list_credentials(
        self,
        customer_id: Optional[str] = None,
        credential_type: Optional[str] = None,
        active_only: bool = True,
    ) -> List[CredentialSafe]:
        """Lista credenziali (senza secrets)"""
        from ..models.database import CustomerCredentialLink
        
        session = self._get_session()
        try:
            if customer_id:
                # Usa la tabella di link per trovare credenziali associate al cliente
                query = session.query(CredentialDB).join(
                    CustomerCredentialLink,
                    CustomerCredentialLink.credential_id == CredentialDB.id
                ).filter(
                    CustomerCredentialLink.customer_id == customer_id
                )
            else:
                query = session.query(CredentialDB)
            
            if credential_type:
                query = query.filter(CredentialDB.credential_type == credential_type)
            if active_only:
                query = query.filter(CredentialDB.active == True)
            
            return [self._to_credential_safe(c) for c in query.all()]
            
        finally:
            session.close()
    
    def list_global_credentials(
        self,
        credential_type: Optional[str] = None,
        active_only: bool = True,
    ) -> List[CredentialSafe]:
        """Lista credenziali globali (senza customer_id)"""
        session = self._get_session()
        try:
            query = session.query(CredentialDB).filter(
                CredentialDB.is_global == True
            )
            
            if credential_type:
                query = query.filter(CredentialDB.credential_type == credential_type)
            if active_only:
                query = query.filter(CredentialDB.active == True)
            
            credentials = []
            for c in query.all():
                cred_safe = self._to_credential_safe(c)
                # Conta quanti clienti usano questa credenziale
                cred_safe.used_by_count = self._count_credential_usage(session, c.id)
                credentials.append(cred_safe)
            
            return credentials
            
        finally:
            session.close()
    
    def _count_credential_usage(self, session, credential_id: str) -> int:
        """Conta quanti clienti utilizzano una credenziale globale"""
        # Questo potrebbe essere implementato con una tabella di join
        # Per ora ritorna 0
        return 0
    
    def list_available_credentials(
        self,
        customer_id: str,
        credential_type: Optional[str] = None,
        active_only: bool = True,
    ) -> List[CredentialSafe]:
        """
        Lista credenziali disponibili per un cliente.
        Include sia le credenziali del cliente che quelle globali.
        """
        session = self._get_session()
        try:
            # Credenziali del cliente
            query = session.query(CredentialDB).filter(
                or_(
                    CredentialDB.customer_id == customer_id,
                    CredentialDB.is_global == True
                )
            )
            
            if credential_type:
                query = query.filter(CredentialDB.credential_type == credential_type)
            if active_only:
                query = query.filter(CredentialDB.active == True)
            
            return [self._to_credential_safe(c) for c in query.all()]
            
        finally:
            session.close()
    
    def get_device_credential(
        self,
        customer_id: str,
        device_name: Optional[str] = None,
    ) -> Optional[Credential]:
        """
        Ottiene credenziali appropriate per un device (decriptate).
        Prima cerca match specifico, poi default del cliente.
        """
        session = self._get_session()
        try:
            # Cerca credenziali specifiche se device_name fornito
            if device_name:
                creds = session.query(CredentialDB).filter(
                    CredentialDB.customer_id == customer_id,
                    CredentialDB.active == True,
                    CredentialDB.device_filter.isnot(None),
                ).all()
                
                import fnmatch
                for cred in creds:
                    if cred.device_filter and fnmatch.fnmatch(device_name, cred.device_filter):
                        return self._decrypt_credential(cred)
            
            # Cerca credenziale di default
            default_cred = session.query(CredentialDB).filter(
                CredentialDB.customer_id == customer_id,
                CredentialDB.is_default == True,
                CredentialDB.active == True,
            ).first()
            
            return self._decrypt_credential(default_cred) if default_cred else None
            
        finally:
            session.close()
    
    def get_default_credentials_by_type(
        self,
        customer_id: str,
        credential_types: List[str] = None,
    ) -> Dict[str, Credential]:
        """
        Ottiene le credenziali di default per ogni tipo richiesto.
        
        Priorità:
        1. Credenziali linkate al cliente con is_default=True
        2. Credenziali linkate al cliente senza is_default
        3. Credenziali legacy (con customer_id diretto)
        4. Credenziali globali non linkate
        
        Args:
            customer_id: ID del cliente
            credential_types: Lista di tipi da cercare (ssh, snmp, wmi, mikrotik)
                             Se None, cerca tutti i tipi disponibili
        
        Returns:
            Dict[tipo -> Credential] con credenziali decriptate
        """
        session = self._get_session()
        result = {}
        
        try:
            # 1. Prima cerca credenziali linkate al cliente
            links = session.query(CredentialLinkDB).filter(
                CredentialLinkDB.customer_id == customer_id
            ).order_by(
                CredentialLinkDB.is_default.desc()  # Default prima
            ).all()
            
            for link in links:
                cred = session.query(CredentialDB).filter(
                    CredentialDB.id == link.credential_id,
                    CredentialDB.active == True
                ).first()
                
                if not cred:
                    continue
                    
                if credential_types and cred.credential_type not in credential_types:
                    continue
                
                if cred.credential_type not in result:
                    result[cred.credential_type] = self._decrypt_credential(cred)
            
            # 2. Poi cerca credenziali legacy e globali per tipi mancanti
            remaining_types = credential_types or ['ssh', 'snmp', 'wmi', 'mikrotik']
            remaining_types = [t for t in remaining_types if t not in result]
            
            if remaining_types:
                query = session.query(CredentialDB).filter(
                    or_(
                        CredentialDB.customer_id == customer_id,
                        CredentialDB.is_global == True
                    ),
                    CredentialDB.active == True,
                    CredentialDB.credential_type.in_(remaining_types)
                ).order_by(
                    (CredentialDB.customer_id == customer_id).desc(),
                    CredentialDB.is_default.desc()
                ).all()
                
                for cred in query:
                    cred_type = cred.credential_type
                    if cred_type not in result:
                        result[cred_type] = self._decrypt_credential(cred)
                    logger.debug(f"Using credential '{cred.name}' ({cred_type}) - global={cred.is_global}")
            
            return result
            
        finally:
            session.close()
    
    def get_credentials_for_auto_detect(
        self,
        customer_id: str,
        open_ports: List[Dict[str, Any]],
    ) -> List[Credential]:
        """
        Ottiene le credenziali da provare in base alle porte aperte.
        
        Logica:
        - SSH (22) aperta → credenziali ssh
        - SNMP (161) aperta → credenziali snmp
        - RDP/SMB/LDAP (3389, 445, 139, 389, 135) → credenziali wmi
        - MikroTik API (8728) → credenziali mikrotik
        
        Args:
            customer_id: ID del cliente
            open_ports: Lista porte aperte [{port, protocol, service, open}]
        
        Returns:
            Lista di Credential ordinate per priorità
        """
        # Determina quali tipi di credenziali servono
        types_needed = set()
        
        # Mappa porte → tipo credenziale
        port_type_map = {
            22: "ssh",
            23: "ssh",  # telnet, proviamo ssh
            161: "snmp",
            162: "snmp",
            3389: "wmi",  # RDP = Windows
            445: "wmi",   # SMB = Windows
            139: "wmi",   # NetBIOS = Windows
            389: "wmi",   # LDAP = Windows AD
            135: "wmi",   # RPC = Windows
            5985: "wmi",  # WinRM = Windows
            5986: "wmi",  # WinRM SSL = Windows
            8728: "mikrotik",
            8729: "mikrotik",
            8291: "mikrotik",  # Winbox
        }
        
        for port_info in open_ports:
            if port_info.get("open"):
                port = port_info.get("port")
                if port in port_type_map:
                    types_needed.add(port_type_map[port])
        
        if not types_needed:
            logger.debug(f"No credential types detected from open ports")
            return []
        
        logger.info(f"Credential types needed based on ports: {types_needed}")
        
        # Ottieni credenziali per i tipi necessari
        creds_by_type = self.get_default_credentials_by_type(
            customer_id, 
            list(types_needed)
        )
        
        # Ordina per priorità: wmi prima (più informativo), poi snmp, poi ssh
        priority_order = ["wmi", "snmp", "ssh", "mikrotik"]
        result = []
        
        for cred_type in priority_order:
            if cred_type in creds_by_type:
                result.append(creds_by_type[cred_type])
        
        # Aggiungi eventuali tipi non in priority_order
        for cred_type, cred in creds_by_type.items():
            if cred not in result:
                result.append(cred)
        
        logger.info(f"Found {len(result)} credentials for auto-detect: {[c.credential_type for c in result]}")
        return result
    
    def update_credential(self, credential_id: str, data: CredentialUpdate) -> Optional[CredentialSafe]:
        """Aggiorna credenziali esistenti"""
        session = self._get_session()
        encryption = get_encryption_service()
        try:
            cred = session.query(CredentialDB).filter(
                CredentialDB.id == credential_id
            ).first()
            
            if not cred:
                return None
            
            # Aggiorna solo i campi forniti
            update_data = data.model_dump(exclude_unset=True)
            
            # Campi da criptare se presenti
            encrypt_fields = ['password', 'ssh_private_key', 'ssh_passphrase', 
                              'snmp_auth_password', 'snmp_priv_password',
                              'api_key', 'api_secret']
            
            for key, value in update_data.items():
                if value is not None:
                    if key in encrypt_fields and value:
                        value = encryption.encrypt(value)
                    setattr(cred, key, value)
            
            session.commit()
            session.refresh(cred)
            
            logger.info(f"Updated credential: {cred.name}")
            return self._to_credential_safe(cred)
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating credential: {e}")
            return None
        finally:
            session.close()
    
    def delete_credential(self, credential_id: str) -> bool:
        """Elimina credenziali"""
        session = self._get_session()
        try:
            cred = session.query(CredentialDB).filter(
                CredentialDB.id == credential_id
            ).first()
            
            if not cred:
                return False
            
            session.delete(cred)
            session.commit()
            
            logger.info(f"Deleted credential: {cred.name}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting credential: {e}")
            return False
        finally:
            session.close()
    
    # ==========================================
    # DEVICE ASSIGNMENTS
    # ==========================================
    
    def assign_device(self, data: DeviceAssignmentCreate) -> DeviceAssignment:
        """Assegna device a cliente"""
        session = self._get_session()
        try:
            # Verifica se già assegnato
            existing = session.query(DeviceAssignmentDB).filter(
                DeviceAssignmentDB.dude_device_id == data.dude_device_id
            ).first()
            
            if existing:
                raise ValueError(f"Device {data.dude_device_id} già assegnato")
            
            assignment = DeviceAssignmentDB(
                dude_device_id=data.dude_device_id,
                dude_device_name=data.dude_device_name,
                customer_id=data.customer_id,
                local_name=data.local_name,
                location=data.location,
                role=data.role.value if data.role else None,
                primary_network_id=data.primary_network_id,
                management_ip=data.management_ip,
                credential_id=data.credential_id,
                contract_type=data.contract_type.value if data.contract_type else None,
                sla_level=data.sla_level.value if data.sla_level else None,
                notes=data.notes,
                tags=data.tags,
                custom_fields=data.custom_fields,
                active=data.active,
                monitored=data.monitored,
            )
            session.add(assignment)
            session.commit()
            session.refresh(assignment)
            
            logger.info(f"Assigned device {data.dude_device_id} to customer {data.customer_id}")
            return DeviceAssignment.model_validate(assignment)
            
        finally:
            session.close()
    
    def get_device_assignment(self, dude_device_id: str) -> Optional[DeviceAssignment]:
        """Ottiene assegnazione per device ID"""
        session = self._get_session()
        try:
            assignment = session.query(DeviceAssignmentDB).filter(
                DeviceAssignmentDB.dude_device_id == dude_device_id
            ).first()
            return DeviceAssignment.model_validate(assignment) if assignment else None
        finally:
            session.close()
    
    def list_device_assignments(
        self,
        customer_id: Optional[str] = None,
        role: Optional[str] = None,
        active_only: bool = True,
    ) -> List[DeviceAssignment]:
        """Lista assegnazioni device"""
        session = self._get_session()
        try:
            query = session.query(DeviceAssignmentDB)
            
            if customer_id:
                query = query.filter(DeviceAssignmentDB.customer_id == customer_id)
            if role:
                query = query.filter(DeviceAssignmentDB.role == role)
            if active_only:
                query = query.filter(DeviceAssignmentDB.active == True)
            
            return [DeviceAssignment.model_validate(a) for a in query.all()]
            
        finally:
            session.close()
    
    def update_device_assignment(
        self,
        dude_device_id: str,
        data: DeviceAssignmentUpdate,
    ) -> Optional[DeviceAssignment]:
        """Aggiorna assegnazione device"""
        session = self._get_session()
        try:
            assignment = session.query(DeviceAssignmentDB).filter(
                DeviceAssignmentDB.dude_device_id == dude_device_id
            ).first()
            
            if not assignment:
                return None
            
            update_data = data.model_dump(exclude_unset=True)
            for key, value in update_data.items():
                if key in ["role", "contract_type", "sla_level"] and value:
                    value = value.value
                setattr(assignment, key, value)
            
            session.commit()
            session.refresh(assignment)
            
            return DeviceAssignment.model_validate(assignment)
            
        finally:
            session.close()
    
    def unassign_device(self, dude_device_id: str) -> bool:
        """Rimuove assegnazione device"""
        session = self._get_session()
        try:
            assignment = session.query(DeviceAssignmentDB).filter(
                DeviceAssignmentDB.dude_device_id == dude_device_id
            ).first()
            
            if not assignment:
                return False
            
            session.delete(assignment)
            session.commit()
            
            logger.info(f"Unassigned device {dude_device_id}")
            return True
            
        finally:
            session.close()

    # ==========================================
    # AGENT ASSIGNMENTS (SONDE)
    # ==========================================
    
    def create_agent(self, data: AgentAssignmentCreate) -> AgentAssignment:
        """Crea nuova sonda per cliente"""
        session = self._get_session()
        try:
            logger.info(f"create_agent called: customer_id={data.customer_id}, name={data.name}, agent_type={getattr(data, 'agent_type', 'mikrotik')}")
            
            # Verifica cliente
            customer = session.query(CustomerDB).filter(
                CustomerDB.id == data.customer_id
            ).first()
            if not customer:
                logger.error(f"Customer not found: {data.customer_id}")
                raise ValueError(f"Cliente {data.customer_id} non trovato")
            
            logger.info(f"Customer found: {customer.name} (id: {customer.id})")
            
            # Encrypt password e ssh_key se presenti
            enc_service = get_encryption_service()
            password = data.password
            if password:
                password = enc_service.encrypt(password)
            
            ssh_key = data.ssh_key
            if ssh_key:
                ssh_key = enc_service.encrypt(ssh_key)
            
            # Encrypt agent_token se presente
            agent_token = getattr(data, 'agent_token', None)
            if agent_token:
                agent_token = enc_service.encrypt(agent_token)
            
            # Estrai agent_type (può essere Enum o string)
            agent_type_value = getattr(data, 'agent_type', 'mikrotik')
            if hasattr(agent_type_value, 'value'):
                agent_type_value = agent_type_value.value
            elif isinstance(agent_type_value, str):
                agent_type_value = agent_type_value.lower()
            else:
                agent_type_value = 'mikrotik'
            
            logger.info(f"Creating agent with type: {agent_type_value}")
            
            # Crea sonda
            agent = AgentAssignmentDB(
                customer_id=data.customer_id,
                dude_agent_id=data.dude_agent_id,
                name=data.name,
                address=data.address,
                port=data.port,
                location=data.location,
                site_name=data.site_name,
                connection_type=data.connection_type,
                username=data.username,
                password=password,
                use_ssl=data.use_ssl,
                ssh_port=data.ssh_port,
                ssh_key=ssh_key,
                # Nuovi campi Docker Agent
                agent_type=agent_type_value,
                agent_api_port=getattr(data, 'agent_api_port', 8080),
                agent_token=agent_token,
                agent_url=getattr(data, 'agent_url', None),
                dns_server=getattr(data, 'dns_server', None),
                # Altri campi
                default_scan_type=data.default_scan_type,
                auto_add_devices=data.auto_add_devices,
                assigned_networks=data.assigned_networks,
                description=data.description,
                notes=data.notes,
                active=data.active,
            )
            
            session.add(agent)
            try:
                session.commit()
                session.refresh(agent)
                logger.info(f"Created agent successfully: id={agent.id}, name={agent.name}, address={agent.address}")
                return AgentAssignment.model_validate(agent)
            except Exception as commit_error:
                session.rollback()
                logger.error(f"Error committing agent to database: {commit_error}", exc_info=True)
                raise ValueError(f"Errore durante salvataggio nel database: {str(commit_error)}")
            
        except ValueError:
            # Re-raise ValueError senza modifiche
            raise
        except Exception as e:
            logger.error(f"Unexpected error creating agent: {e}", exc_info=True)
            if session:
                session.rollback()
            raise ValueError(f"Errore durante creazione sonda: {str(e)}")
        finally:
            if session:
                session.close()
    
    def get_agent(self, agent_id: str, include_password: bool = False) -> Optional[AgentAssignment]:
        """Ottiene sonda per ID"""
        session = self._get_session()
        try:
            agent = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.id == agent_id
            ).first()
            
            if not agent:
                return None
            
            result = AgentAssignment.model_validate(agent)
            
            enc_service = get_encryption_service()
            
            # Decrypt password se richiesto
            if include_password and agent.password:
                try:
                    # Tenta sempre la decriptazione - la password nel DB è sempre criptata
                    decrypted = enc_service.decrypt(agent.password)
                    result.password = decrypted
                    logger.debug(f"Password decrypted successfully for agent {agent_id}")
                except Exception as e:
                    # Se la decriptazione fallisce, potrebbe essere già in chiaro (legacy) o errore di encryption
                    logger.warning(f"Failed to decrypt password for agent {agent_id}: {e}. Password might be in plain text (legacy).")
                    # Prova a usare direttamente - potrebbe essere già in chiaro
                    result.password = agent.password
            else:
                result.password = None
            
            # Decrypt agent_token se presente
            if include_password and agent.agent_token:
                try:
                    result.agent_token = enc_service.decrypt(agent.agent_token)
                except:
                    result.agent_token = agent.agent_token  # Fallback a valore in chiaro
            
            return result
            
        finally:
            session.close()
    
    def list_agents(
        self,
        customer_id: Optional[str] = None,
        active_only: bool = True,
        include_password: bool = False,
    ) -> List[AgentAssignmentSafe]:
        """Lista sonde"""
        session = self._get_session()
        try:
            query = session.query(AgentAssignmentDB)
            
            if customer_id:
                query = query.filter(AgentAssignmentDB.customer_id == customer_id)
            if active_only:
                query = query.filter(AgentAssignmentDB.active == True)
            
            agents = query.order_by(AgentAssignmentDB.name).all()
            
            results = []
            for agent in agents:
                safe = AgentAssignmentSafe.model_validate(agent)
                results.append(safe)
            
            return results
            
        finally:
            session.close()
    
    def update_agent(self, agent_id: str, data: AgentAssignmentUpdate) -> Optional[AgentAssignment]:
        """Aggiorna sonda"""
        session = self._get_session()
        try:
            agent = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.id == agent_id
            ).first()
            
            if not agent:
                return None
            
            update_data = data.model_dump(exclude_unset=True)
            
            # Encrypt password, ssh_key e agent_token se presenti
            enc_service = get_encryption_service()
            
            # PRESERVA password esistente se non viene fornita una nuova
            if "password" in update_data:
                if update_data["password"] and update_data["password"].strip():
                    # Nuova password fornita: encrypta e salva
                    update_data["password"] = enc_service.encrypt(update_data["password"])
                else:
                    # Password vuota o None: preserva quella esistente
                    logger.debug(f"Preserving existing password for agent {agent_id}")
                    del update_data["password"]
            
            # PRESERVA ssh_key esistente se non viene fornita una nuova
            if "ssh_key" in update_data:
                if update_data["ssh_key"] and update_data["ssh_key"].strip():
                    update_data["ssh_key"] = enc_service.encrypt(update_data["ssh_key"])
                else:
                    logger.debug(f"Preserving existing ssh_key for agent {agent_id}")
                    del update_data["ssh_key"]
            
            # PRESERVA agent_token esistente se non viene fornito uno nuovo
            if "agent_token" in update_data:
                if update_data["agent_token"] and update_data["agent_token"].strip():
                    update_data["agent_token"] = enc_service.encrypt(update_data["agent_token"])
                else:
                    logger.debug(f"Preserving existing agent_token for agent {agent_id}")
                    del update_data["agent_token"]
            
            for key, value in update_data.items():
                setattr(agent, key, value)
            
            session.commit()
            session.refresh(agent)
            
            logger.info(f"Updated agent: {agent.name}")
            return AgentAssignment.model_validate(agent)
            
        finally:
            session.close()
    
    async def delete_agent(self, agent_id: str) -> bool:
        """
        Elimina sonda.
        Chiude connessioni WebSocket attive prima di eliminare dal database.
        """
        session = self._get_session()
        agent = None
        try:
            # Normalizza ID (rimuovi spazi, trim)
            agent_id = agent_id.strip() if agent_id else None
            if not agent_id:
                logger.error("delete_agent called with empty agent_id")
                return False
            
            logger.info(f"Deleting agent: agent_id='{agent_id}' (type: {type(agent_id).__name__}, len: {len(agent_id)})")
            
            # Prova prima con match esatto
            agent = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.id == agent_id
            ).first()
            
            # Se non trovato, prova a cercare anche per nome (fallback)
            if not agent:
                logger.warning(f"Agent not found by ID '{agent_id}', trying by name...")
                agent = session.query(AgentAssignmentDB).filter(
                    AgentAssignmentDB.name == agent_id
                ).first()
                if agent:
                    logger.info(f"Found agent by name: {agent.name} (id: {agent.id})")
            
            if not agent:
                logger.error(f"Agent not found: agent_id='{agent_id}'")
                # Log tutti gli agent disponibili per debug
                all_agents = session.query(AgentAssignmentDB).all()
                logger.debug(f"Available agents: {[(a.id, a.name) for a in all_agents]}")
                return False
            
            # Verifica se l'agent è usato come gateway in reti o come riferimento in altri agent
            from ..models.database import Network
            networks_using_agent = session.query(Network).filter(
                Network.gateway_agent_id == agent_id
            ).all()
            
            # Verifica se altri agent usano questo agent come docker_agent_id o arp_gateway_agent_id
            agents_using_as_docker = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.docker_agent_id == agent_id
            ).all()
            agents_using_as_arp = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.arp_gateway_agent_id == agent_id
            ).all()
            
            if networks_using_agent or agents_using_as_docker or agents_using_as_arp:
                logger.warning(f"Agent {agent.name} (id: {agent_id}) is referenced by:")
                if networks_using_agent:
                    logger.warning(f"  - {len(networks_using_agent)} network(s): {[n.name for n in networks_using_agent]}")
                if agents_using_as_docker:
                    logger.warning(f"  - {len(agents_using_as_docker)} agent(s) as docker_agent: {[a.name for a in agents_using_as_docker]}")
                if agents_using_as_arp:
                    logger.warning(f"  - {len(agents_using_as_arp)} agent(s) as arp_gateway: {[a.name for a in agents_using_as_arp]}")
                
                # Rimuovi i riferimenti prima di eliminare
                for network in networks_using_agent:
                    logger.info(f"Removing gateway_agent_id from network {network.name}")
                    network.gateway_agent_id = None
                
                for other_agent in agents_using_as_docker:
                    logger.info(f"Removing docker_agent_id from agent {other_agent.name}")
                    other_agent.docker_agent_id = None
                
                for other_agent in agents_using_as_arp:
                    logger.info(f"Removing arp_gateway_agent_id from agent {other_agent.name}")
                    other_agent.arp_gateway_agent_id = None
                
                # Salva le modifiche
                if networks_using_agent or agents_using_as_docker or agents_using_as_arp:
                    session.commit()
                    logger.info("References removed successfully")
            
            # Verifica e chiudi connessione WebSocket se presente
            # Usa dude_agent_id o un identificatore univoco per trovare la connessione
            ws_agent_id = None
            if agent.agent_type == "docker" and agent.dude_agent_id:
                ws_agent_id = agent.dude_agent_id
            elif agent.name:
                # Fallback: usa il nome come identificatore
                ws_agent_id = agent.name
            
            if ws_agent_id:
                try:
                    from ..services.websocket_hub import get_websocket_hub
                    hub = get_websocket_hub()
                    
                    if await hub.is_connected(ws_agent_id):
                        logger.info(f"Closing WebSocket connection for agent {ws_agent_id} before deletion")
                        await hub.disconnect(ws_agent_id)
                        
                        # Attendi conferma disconnessione (max 5s)
                        for _ in range(10):
                            await asyncio.sleep(0.5)
                            if not await hub.is_connected(ws_agent_id):
                                logger.info(f"WebSocket connection closed for agent {ws_agent_id}")
                                break
                        else:
                            logger.warning(f"WebSocket connection still active for {ws_agent_id} after timeout")
                except Exception as e:
                    logger.warning(f"Error closing WebSocket connection for agent {ws_agent_id}: {e}")
                    # Continua con eliminazione anche se WebSocket close fallisce
            
            # Elimina dal database
            agent_name = agent.name
            session.delete(agent)
            try:
                session.commit()
                logger.info(f"Deleted agent: {agent_name} (id: {agent_id})")
                return True
            except Exception as commit_error:
                session.rollback()
                logger.error(f"Error committing agent deletion: {commit_error}", exc_info=True)
                # Se è un errore di foreign key, fornisci un messaggio più chiaro
                error_str = str(commit_error)
                if "foreign key" in error_str.lower() or "violates" in error_str.lower():
                    logger.error(f"Foreign key constraint violation. Agent is still referenced somewhere.")
                    raise ValueError(f"Impossibile eliminare l'agent '{agent_name}': è ancora referenziato da altre entità. Verifica reti o altri agent che lo utilizzano.")
                raise
            
        except ValueError:
            # Re-raise ValueError senza modifiche
            raise
        except Exception as e:
            logger.error(f"Error deleting agent agent_id='{agent_id}': {e}", exc_info=True)
            if session:
                session.rollback()
            return False
        finally:
            if session:
                session.close()
    
    def update_agent_status(self, agent_id: str, status: str, version: str = None) -> bool:
        """Aggiorna stato sonda"""
        session = self._get_session()
        try:
            agent = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.id == agent_id
            ).first()
            
            if not agent:
                return False
            
            agent.status = status
            agent.last_seen = datetime.utcnow()
            if version:
                agent.version = version
            
            session.commit()
            return True
            
        finally:
            session.close()
    
    def get_agent_by_unique_id(self, agent_unique_id: str, address: str = None) -> Optional[AgentAssignmentSafe]:
        """Trova agent per ID univoco (usato per auto-registrazione)"""
        from loguru import logger
        session = self._get_session()
        try:
            # 1. Cerca per dude_agent_id (campo dedicato per agent_id auto-registrati)
            agent = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.dude_agent_id == agent_unique_id
            ).first()
            
            if agent:
                logger.debug(f"Found agent by dude_agent_id: {agent_unique_id} -> DB ID {agent.id}")
                return self._to_agent_safe(agent)
            
            logger.debug(f"No agent found with dude_agent_id={agent_unique_id}, trying other methods...")
            
            # 2. Cerca per ID database diretto
            agent = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.id == agent_unique_id
            ).first()
            
            if agent:
                return self._to_agent_safe(agent)
            
            # 3. Cerca per nome esatto (display name)
            agent = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.name == agent_unique_id
            ).first()
            
            if agent:
                return self._to_agent_safe(agent)
            
            # 4. Cerca per nome base esatto (es: "agent-PX-OVH-51-1234" -> cerca "PX-OVH-51")
            # IMPORTANTE: match solo ESATTO, no match parziali che causano falsi positivi
            import re
            name_match = re.match(r'^agent-(.+?)(-\d+)?$', agent_unique_id)
            if name_match:
                base_name = name_match.group(1)
                # Solo match esatto sul nome base
                agent = session.query(AgentAssignmentDB).filter(
                    AgentAssignmentDB.name == base_name
                ).first()
                
                if agent:
                    return self._to_agent_safe(agent)
            
            # NON usare match parziale - troppi falsi positivi
            # "OVH" in "agent-PX-OVH-51" = True (sbagliato!)
            # L'agent deve essere identificato solo per ID esatto o nome esatto
            
            return None
            
        finally:
            session.close()
    
    def get_agent_token(self, agent_unique_id: str) -> Optional[str]:
        """Ottiene il token criptato dell'agent per autenticazione WebSocket"""
        session = self._get_session()
        try:
            # 1. Cerca per dude_agent_id (campo dedicato per agent_id auto-registrati)
            agent = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.dude_agent_id == agent_unique_id
            ).first()
            
            if not agent:
                # 2. Cerca per ID database diretto
                agent = session.query(AgentAssignmentDB).filter(
                    AgentAssignmentDB.id == agent_unique_id
                ).first()
            
            if not agent:
                # 3. Cerca per nome esatto
                agent = session.query(AgentAssignmentDB).filter(
                    AgentAssignmentDB.name == agent_unique_id
                ).first()
            
            if not agent:
                # 4. Cerca per pattern agent-name-timestamp
                import re
                name_match = re.match(r'^agent-(.+?)-\d+$', agent_unique_id)
                if name_match:
                    base_name = name_match.group(1)
                    agent = session.query(AgentAssignmentDB).filter(
                        AgentAssignmentDB.name == base_name
                    ).first()
            
            if not agent:
                # 5. Cerca per nome parziale (fallback)
                all_agents = session.query(AgentAssignmentDB).filter(
                    AgentAssignmentDB.active == True
                ).all()
                for a in all_agents:
                    if a.name and a.name in agent_unique_id:
                        agent = a
                        break
            
            return agent.agent_token if agent else None
            
        finally:
            session.close()
    
    def update_agent_address(self, agent_id: str, new_address: str) -> bool:
        """Aggiorna l'indirizzo IP di un agent"""
        session = self._get_session()
        try:
            agent = session.query(AgentAssignmentDB).filter(
                AgentAssignmentDB.id == agent_id
            ).first()
            
            if not agent:
                return False
            
            old_address = agent.address
            agent.address = new_address
            agent.agent_url = f"http://{new_address}:{agent.agent_api_port or 8080}"
            agent.updated_at = datetime.utcnow()
            
            session.commit()
            
            logger.info(f"Updated agent {agent.name} address: {old_address} -> {new_address}")
            return True
            
        finally:
            session.close()
    
    def _to_agent_safe(self, agent: AgentAssignmentDB) -> AgentAssignmentSafe:
        """Converte agent DB in versione safe"""
        return AgentAssignmentSafe(
            id=agent.id,
            customer_id=agent.customer_id or "",
            name=agent.name,
            address=agent.address,
            port=agent.port or 8728,
            agent_type=agent.agent_type or "mikrotik",
            dude_agent_id=agent.dude_agent_id,
            status=agent.status or "unknown",
            last_seen=agent.last_seen,
            version=agent.version,
            assigned_networks=agent.assigned_networks.split(",") if agent.assigned_networks else [],
            use_ssl=agent.use_ssl or False,
            ssh_port=agent.ssh_port or 22,
            agent_api_port=agent.agent_api_port or 8080,
            agent_url=agent.agent_url,
            dns_server=agent.dns_server,
            active=agent.active if agent.active is not None else False,
            created_at=agent.created_at,
            updated_at=agent.updated_at,
        )
    
    # ==========================================
    # CREDENTIAL LINKS (Archivio Centralizzato)
    # ==========================================
    
    def link_credential_to_customer(
        self, 
        customer_id: str, 
        credential_id: str, 
        is_default: bool = False,
        notes: str = None
    ) -> Dict[str, Any]:
        """Associa una credenziale centrale a un cliente"""
        session = self._get_session()
        try:
            # Verifica che cliente e credenziale esistano
            customer = session.query(CustomerDB).filter(CustomerDB.id == customer_id).first()
            credential = session.query(CredentialDB).filter(CredentialDB.id == credential_id).first()
            
            if not customer:
                raise ValueError(f"Cliente {customer_id} non trovato")
            if not credential:
                raise ValueError(f"Credenziale {credential_id} non trovata")
            
            # Verifica se il link esiste già
            existing = session.query(CredentialLinkDB).filter(
                CredentialLinkDB.customer_id == customer_id,
                CredentialLinkDB.credential_id == credential_id
            ).first()
            
            if existing:
                # Aggiorna il link esistente
                existing.is_default = is_default
                if notes:
                    existing.notes = notes
                session.commit()
                logger.info(f"Updated credential link: {credential.name} -> {customer.name}")
                return {
                    "id": existing.id,
                    "customer_id": customer_id,
                    "credential_id": credential_id,
                    "is_default": is_default,
                    "updated": True
                }
            
            # Se is_default, rimuovi default da altre credenziali dello stesso tipo
            if is_default:
                session.query(CredentialLinkDB).filter(
                    CredentialLinkDB.customer_id == customer_id,
                    CredentialLinkDB.credential_id.in_(
                        session.query(CredentialDB.id).filter(
                            CredentialDB.credential_type == credential.credential_type
                        )
                    )
                ).update({"is_default": False}, synchronize_session=False)
            
            # Crea nuovo link
            from ..models.database import generate_uuid
            link = CredentialLinkDB(
                id=generate_uuid(),
                customer_id=customer_id,
                credential_id=credential_id,
                is_default=is_default,
                notes=notes
            )
            session.add(link)
            session.commit()
            
            logger.info(f"Linked credential {credential.name} to customer {customer.name}")
            return {
                "id": link.id,
                "customer_id": customer_id,
                "credential_id": credential_id,
                "is_default": is_default,
                "created": True
            }
            
        finally:
            session.close()
    
    def unlink_credential_from_customer(self, customer_id: str, credential_id: str) -> bool:
        """Rimuove l'associazione tra credenziale e cliente"""
        session = self._get_session()
        try:
            link = session.query(CredentialLinkDB).filter(
                CredentialLinkDB.customer_id == customer_id,
                CredentialLinkDB.credential_id == credential_id
            ).first()
            
            if not link:
                return False
            
            session.delete(link)
            session.commit()
            
            logger.info(f"Unlinked credential {credential_id} from customer {customer_id}")
            return True
            
        finally:
            session.close()
    
    def get_customer_credentials(self, customer_id: str, include_password: bool = False) -> List[Dict[str, Any]]:
        """
        Ottiene tutte le credenziali associate a un cliente (via link).
        Include info sul link (is_default) e sulla credenziale.
        """
        session = self._get_session()
        try:
            links = session.query(CredentialLinkDB).filter(
                CredentialLinkDB.customer_id == customer_id
            ).all()
            
            result = []
            for link in links:
                cred = session.query(CredentialDB).filter(
                    CredentialDB.id == link.credential_id
                ).first()
                
                if cred:
                    cred_data = {
                        "id": cred.id,
                        "name": cred.name,
                        "credential_type": cred.credential_type,
                        "username": cred.username,
                        "description": cred.description,
                        "is_default": link.is_default,
                        "link_id": link.id,
                        "link_notes": link.notes,
                        "active": cred.active,
                        # Info per UI
                        "ssh_port": cred.ssh_port,
                        "snmp_community": cred.snmp_community,
                        "snmp_version": cred.snmp_version,
                        "snmp_port": cred.snmp_port,
                        "wmi_domain": cred.wmi_domain,
                        "mikrotik_api_port": cred.mikrotik_api_port,
                    }
                    
                    if include_password:
                        enc = get_encryption_service()
                        cred_data["password"] = enc.decrypt(cred.password) if cred.password else None
                        cred_data["ssh_private_key"] = enc.decrypt(cred.ssh_private_key) if cred.ssh_private_key else None
                    
                    result.append(cred_data)
            
            return result
            
        finally:
            session.close()
    
    def get_all_credentials(self, include_usage: bool = True) -> List[Dict[str, Any]]:
        """
        Ottiene tutte le credenziali dall'archivio centrale.
        Opzionalmente include il conteggio di utilizzo (clienti e device).
        """
        session = self._get_session()
        try:
            creds = session.query(CredentialDB).filter(
                CredentialDB.active == True
            ).order_by(CredentialDB.name).all()
            
            result = []
            for cred in creds:
                cred_data = {
                    "id": cred.id,
                    "name": cred.name,
                    "credential_type": cred.credential_type,
                    "username": cred.username,
                    "description": cred.description,
                    "active": cred.active,
                    "created_at": cred.created_at.isoformat() if cred.created_at else None,
                    # Campi specifici tipo
                    "ssh_port": cred.ssh_port,
                    "snmp_community": cred.snmp_community,
                    "snmp_version": cred.snmp_version,
                    "wmi_domain": cred.wmi_domain,
                    "mikrotik_api_port": cred.mikrotik_api_port,
                }
                
                if include_usage:
                    # Conta quanti clienti usano questa credenziale
                    customer_count = session.query(CredentialLinkDB).filter(
                        CredentialLinkDB.credential_id == cred.id
                    ).count()
                    
                    # Conta quanti device la usano direttamente
                    try:
                        from ..models.inventory import InventoryDevice
                        device_count = session.query(InventoryDevice).filter(
                            InventoryDevice.credential_id == cred.id
                        ).count()
                    except (ImportError, AttributeError) as e:
                        logger.warning(f"Could not import InventoryDevice for usage count: {e}")
                        device_count = 0
                    
                    cred_data["customer_count"] = customer_count
                    cred_data["device_count"] = device_count
                    cred_data["total_usage"] = customer_count + device_count
                
                result.append(cred_data)
            
            return result
            
        finally:
            session.close()
    
    def get_customer_default_credential(
        self, 
        customer_id: str, 
        credential_type: str,
        include_password: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Ottiene la credenziale di default per un tipo specifico per un cliente.
        Cerca tra le credenziali linkate al cliente con is_default=True.
        """
        session = self._get_session()
        try:
            # Cerca link con is_default per questo tipo
            link = session.query(CredentialLinkDB).join(
                CredentialDB, CredentialLinkDB.credential_id == CredentialDB.id
            ).filter(
                CredentialLinkDB.customer_id == customer_id,
                CredentialLinkDB.is_default == True,
                CredentialDB.credential_type == credential_type,
                CredentialDB.active == True
            ).first()
            
            if not link:
                return None
            
            cred = session.query(CredentialDB).filter(
                CredentialDB.id == link.credential_id
            ).first()
            
            if not cred:
                return None
            
            result = {
                "id": cred.id,
                "name": cred.name,
                "credential_type": cred.credential_type,
                "username": cred.username,
                "ssh_port": cred.ssh_port,
                "snmp_community": cred.snmp_community,
                "snmp_version": cred.snmp_version,
                "snmp_port": cred.snmp_port,
                "wmi_domain": cred.wmi_domain,
                "mikrotik_api_port": cred.mikrotik_api_port,
            }
            
            if include_password:
                enc = get_encryption_service()
                result["password"] = enc.decrypt(cred.password) if cred.password else None
                result["ssh_private_key"] = enc.decrypt(cred.ssh_private_key) if cred.ssh_private_key else None
            
            return result
            
        finally:
            session.close()
    
    def set_customer_default_credential(self, customer_id: str, credential_id: str) -> bool:
        """
        Imposta una credenziale come default per il suo tipo per un cliente.
        Rimuove il flag default da altre credenziali dello stesso tipo.
        """
        session = self._get_session()
        try:
            # Ottieni la credenziale per sapere il tipo
            cred = session.query(CredentialDB).filter(
                CredentialDB.id == credential_id
            ).first()
            
            if not cred:
                return False
            
            # Verifica che esista il link
            link = session.query(CredentialLinkDB).filter(
                CredentialLinkDB.customer_id == customer_id,
                CredentialLinkDB.credential_id == credential_id
            ).first()
            
            if not link:
                # Crea il link se non esiste
                self.link_credential_to_customer(customer_id, credential_id, is_default=True)
            else:
                # Rimuovi default da altre credenziali dello stesso tipo
                other_links = session.query(CredentialLinkDB).join(
                    CredentialDB, CredentialLinkDB.credential_id == CredentialDB.id
                ).filter(
                    CredentialLinkDB.customer_id == customer_id,
                    CredentialDB.credential_type == cred.credential_type,
                    CredentialLinkDB.id != link.id
                ).all()
                
                for other in other_links:
                    other.is_default = False
                
                # Imposta questo come default
                link.is_default = True
                session.commit()
            
            logger.info(f"Set {cred.name} as default {cred.credential_type} for customer {customer_id}")
            return True
            
        finally:
            session.close()


# Singleton
_customer_service: Optional[CustomerService] = None


def get_customer_service() -> CustomerService:
    """Get singleton CustomerService instance"""
    global _customer_service
    if _customer_service is None:
        _customer_service = CustomerService()
    return _customer_service
