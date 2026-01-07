"""
DaDude - PKI Service
Gestione CA self-signed e certificati client per mTLS
"""
import os
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from loguru import logger


class PKIService:
    """
    Servizio PKI per gestione certificati mTLS.
    Genera CA root, certificati server e certificati client per agent.
    """
    
    def __init__(self, pki_dir: str = "data/pki"):
        self.pki_dir = Path(pki_dir)
        self.pki_dir.mkdir(parents=True, exist_ok=True)
        (self.pki_dir / "agents").mkdir(exist_ok=True)
        
        self.ca_key_path = self.pki_dir / "ca.key"
        self.ca_cert_path = self.pki_dir / "ca.crt"
        self.server_key_path = self.pki_dir / "server.key"
        self.server_cert_path = self.pki_dir / "server.crt"
        self.revoked_path = self.pki_dir / "revoked.json"
        
        self._ca_key: Optional[rsa.RSAPrivateKey] = None
        self._ca_cert: Optional[x509.Certificate] = None
    
    def _load_or_generate_ca(self) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Carica CA esistente o ne genera una nuova"""
        if self._ca_key and self._ca_cert:
            return self._ca_key, self._ca_cert
        
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            # Carica CA esistente
            with open(self.ca_key_path, "rb") as f:
                self._ca_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(self.ca_cert_path, "rb") as f:
                self._ca_cert = x509.load_pem_x509_certificate(
                    f.read(), backend=default_backend()
                )
            logger.info("CA certificate loaded from disk")
        else:
            # Genera nuova CA
            self._ca_key, self._ca_cert = self._generate_ca()
            logger.info("New CA certificate generated")
        
        return self._ca_key, self._ca_cert
    
    def _generate_ca(self) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Genera CA root self-signed"""
        # Genera chiave privata RSA 4096 bit
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Crea certificato CA
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Italia"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DaDude"),
            x509.NameAttribute(NameOID.COMMON_NAME, "DaDude Root CA"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 anni
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        
        # Salva su disco
        with open(self.ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(self.ca_key_path, 0o600)
        
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        return key, cert
    
    def generate_server_certificate(
        self,
        common_name: str = "dadude-server",
        san_dns: Optional[list] = None,
        san_ips: Optional[list] = None,
        validity_days: int = 365
    ) -> Tuple[bytes, bytes]:
        """
        Genera certificato server per TLS.
        
        Returns:
            Tuple[bytes, bytes]: (private_key_pem, certificate_pem)
        """
        ca_key, ca_cert = self._load_or_generate_ca()
        
        # Genera chiave server
        server_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DaDude"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # SAN (Subject Alternative Names)
        san_entries = []
        if san_dns:
            san_entries.extend([x509.DNSName(dns) for dns in san_dns])
        if san_ips:
            from ipaddress import ip_address
            san_entries.extend([x509.IPAddress(ip_address(ip)) for ip in san_ips])
        if not san_entries:
            san_entries = [x509.DNSName("localhost"), x509.DNSName(common_name)]
        
        # Crea certificato
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        
        key_pem = server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        
        # Salva su disco
        with open(self.server_key_path, "wb") as f:
            f.write(key_pem)
        os.chmod(self.server_key_path, 0o600)
        
        with open(self.server_cert_path, "wb") as f:
            f.write(cert_pem)
        
        logger.info(f"Server certificate generated: {common_name}")
        return key_pem, cert_pem
    
    def generate_agent_certificate(
        self,
        agent_id: str,
        agent_name: str,
        validity_days: int = 365
    ) -> Dict[str, bytes]:
        """
        Genera certificato client per un agent.
        
        Returns:
            Dict con: private_key, certificate, ca_certificate
        """
        ca_key, ca_cert = self._load_or_generate_ca()
        
        # Verifica se certificato esiste già
        agent_key_path = self.pki_dir / "agents" / f"{agent_id}.key"
        agent_cert_path = self.pki_dir / "agents" / f"{agent_id}.crt"
        
        # Genera chiave agent
        agent_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Subject con agent_id come CN
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DaDude"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Agents"),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, agent_id),
        ])
        
        # Crea certificato client
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(agent_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(f"urn:dadude:agent:{agent_id}")
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        
        key_pem = agent_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        
        # Salva su disco
        with open(agent_key_path, "wb") as f:
            f.write(key_pem)
        os.chmod(agent_key_path, 0o600)
        
        with open(agent_cert_path, "wb") as f:
            f.write(cert_pem)
        
        # Salva metadata
        meta_path = self.pki_dir / "agents" / f"{agent_id}.json"
        with open(meta_path, "w") as f:
            json.dump({
                "agent_id": agent_id,
                "agent_name": agent_name,
                "issued_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(days=validity_days)).isoformat(),
                "serial_number": str(cert.serial_number),
            }, f, indent=2)
        
        logger.info(f"Agent certificate generated: {agent_id} ({agent_name})")
        
        return {
            "private_key": key_pem,
            "certificate": cert_pem,
            "ca_certificate": ca_pem,
        }
    
    def get_agent_certificate(self, agent_id: str) -> Optional[Dict[str, bytes]]:
        """Recupera certificato agent esistente"""
        agent_key_path = self.pki_dir / "agents" / f"{agent_id}.key"
        agent_cert_path = self.pki_dir / "agents" / f"{agent_id}.crt"
        
        if not agent_key_path.exists() or not agent_cert_path.exists():
            return None
        
        ca_key, ca_cert = self._load_or_generate_ca()
        
        with open(agent_key_path, "rb") as f:
            key_pem = f.read()
        with open(agent_cert_path, "rb") as f:
            cert_pem = f.read()
        
        return {
            "private_key": key_pem,
            "certificate": cert_pem,
            "ca_certificate": ca_cert.public_bytes(serialization.Encoding.PEM),
        }
    
    def verify_client_certificate(self, cert_pem: bytes) -> Optional[str]:
        """
        Verifica certificato client e ritorna agent_id se valido.
        
        Returns:
            agent_id se valido, None altrimenti
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            
            # Verifica scadenza
            if cert.not_valid_after < datetime.utcnow():
                logger.warning("Certificate expired")
                return None
            
            if cert.not_valid_before > datetime.utcnow():
                logger.warning("Certificate not yet valid")
                return None
            
            # Estrai agent_id dal CN
            for attr in cert.subject:
                if attr.oid == NameOID.COMMON_NAME:
                    agent_id = attr.value
                    break
            else:
                logger.warning("No CN in certificate")
                return None
            
            # Verifica che non sia revocato
            if self._is_revoked(agent_id, str(cert.serial_number)):
                logger.warning(f"Certificate revoked: {agent_id}")
                return None
            
            # Verifica firma (CA)
            ca_key, ca_cert = self._load_or_generate_ca()
            try:
                ca_cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_algorithm_parameters,
                )
            except Exception as e:
                logger.warning(f"Certificate signature verification failed: {e}")
                return None
            
            return agent_id
            
        except Exception as e:
            logger.error(f"Certificate verification error: {e}")
            return None
    
    def revoke_certificate(self, agent_id: str) -> bool:
        """Revoca certificato agent"""
        agent_cert_path = self.pki_dir / "agents" / f"{agent_id}.crt"
        
        if not agent_cert_path.exists():
            return False
        
        # Carica certificato per ottenere serial
        with open(agent_cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Aggiungi a lista revocati
        revoked = self._load_revoked()
        revoked[agent_id] = {
            "serial_number": str(cert.serial_number),
            "revoked_at": datetime.utcnow().isoformat(),
        }
        self._save_revoked(revoked)
        
        # Rimuovi file certificato
        agent_cert_path.unlink(missing_ok=True)
        (self.pki_dir / "agents" / f"{agent_id}.key").unlink(missing_ok=True)
        (self.pki_dir / "agents" / f"{agent_id}.json").unlink(missing_ok=True)
        
        logger.info(f"Certificate revoked: {agent_id}")
        return True
    
    def _is_revoked(self, agent_id: str, serial_number: str) -> bool:
        """Verifica se certificato è revocato"""
        revoked = self._load_revoked()
        if agent_id in revoked:
            return revoked[agent_id].get("serial_number") == serial_number
        return False
    
    def _load_revoked(self) -> Dict[str, Any]:
        """Carica lista certificati revocati"""
        if self.revoked_path.exists():
            with open(self.revoked_path) as f:
                return json.load(f)
        return {}
    
    def _save_revoked(self, revoked: Dict[str, Any]):
        """Salva lista certificati revocati"""
        with open(self.revoked_path, "w") as f:
            json.dump(revoked, f, indent=2)
    
    def get_ca_certificate(self) -> bytes:
        """Ritorna certificato CA in formato PEM"""
        ca_key, ca_cert = self._load_or_generate_ca()
        return ca_cert.public_bytes(serialization.Encoding.PEM)
    
    def list_agent_certificates(self) -> list:
        """Lista tutti i certificati agent emessi"""
        agents = []
        agents_dir = self.pki_dir / "agents"
        
        for meta_file in agents_dir.glob("*.json"):
            with open(meta_file) as f:
                agents.append(json.load(f))
        
        return agents
    
    def get_certificate_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Ottiene info su certificato agent"""
        meta_path = self.pki_dir / "agents" / f"{agent_id}.json"
        if meta_path.exists():
            with open(meta_path) as f:
                return json.load(f)
        return None
    
    def check_expiring_soon(self, days: int = 30) -> list:
        """Trova certificati che scadono entro N giorni"""
        expiring = []
        threshold = datetime.utcnow() + timedelta(days=days)
        
        for cert_info in self.list_agent_certificates():
            expires = datetime.fromisoformat(cert_info["expires_at"])
            if expires < threshold:
                cert_info["days_until_expiry"] = (expires - datetime.utcnow()).days
                expiring.append(cert_info)
        
        return expiring


# Singleton
_pki_service: Optional[PKIService] = None


def get_pki_service() -> PKIService:
    """Ottiene istanza singleton del PKI service"""
    global _pki_service
    if _pki_service is None:
        _pki_service = PKIService()
    return _pki_service

