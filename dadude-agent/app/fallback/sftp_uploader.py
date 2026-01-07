"""
DaDude Agent - SFTP Fallback Uploader
Upload crittografato dei dati pendenti quando il server WebSocket è irraggiungibile
"""
import asyncio
import gzip
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from loguru import logger

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@dataclass
class SFTPConfig:
    """Configurazione SFTP"""
    enabled: bool = False
    host: str = ""
    port: int = 22
    username: str = ""
    password: Optional[str] = None
    private_key_path: Optional[str] = None
    remote_path: str = "/incoming"
    server_public_key_path: Optional[str] = None  # Per crittografia
    timeout_seconds: int = 30
    
    @classmethod
    def from_dict(cls, data: dict) -> "SFTPConfig":
        return cls(
            enabled=data.get("enabled", False),
            host=data.get("host", ""),
            port=data.get("port", 22),
            username=data.get("username", ""),
            password=data.get("password"),
            private_key_path=data.get("private_key_path"),
            remote_path=data.get("remote_path", "/incoming"),
            server_public_key_path=data.get("server_public_key_path"),
            timeout_seconds=data.get("timeout_seconds", 30),
        )
    
    @classmethod
    def from_env(cls) -> "SFTPConfig":
        """Crea config da variabili ambiente"""
        return cls(
            enabled=os.getenv("SFTP_ENABLED", "false").lower() == "true",
            host=os.getenv("SFTP_HOST", ""),
            port=int(os.getenv("SFTP_PORT", "22")),
            username=os.getenv("SFTP_USERNAME", ""),
            password=os.getenv("SFTP_PASSWORD"),
            private_key_path=os.getenv("SFTP_PRIVATE_KEY_PATH"),
            remote_path=os.getenv("SFTP_REMOTE_PATH", "/incoming"),
            server_public_key_path=os.getenv("SFTP_SERVER_PUBLIC_KEY_PATH"),
            timeout_seconds=int(os.getenv("SFTP_TIMEOUT", "30")),
        )


class SFTPFallbackUploader:
    """
    Uploader SFTP per fallback quando server WebSocket irraggiungibile.
    
    Funzionamento:
    1. Raccoglie dati pendenti dalla coda
    2. Serializza in JSON
    3. Comprime con gzip
    4. Cripta con chiave pubblica del server (hybrid: RSA + AES-GCM)
    5. Upload via SFTP
    6. Il server può poi processare i file dalla directory incoming
    
    Formato file: {agent_id}_{timestamp}.enc
    Struttura file crittografato:
    - 4 bytes: lunghezza chiave AES crittografata
    - N bytes: chiave AES crittografata con RSA
    - 12 bytes: nonce AES-GCM
    - M bytes: dati crittografati con AES-GCM
    """
    
    def __init__(
        self,
        agent_id: str,
        config: Optional[SFTPConfig] = None,
    ):
        self.agent_id = agent_id
        self.config = config or SFTPConfig.from_env()
        
        self._server_public_key: Optional[rsa.RSAPublicKey] = None
        
        # Carica chiave pubblica server se presente
        if self.config.server_public_key_path:
            self._load_server_public_key()
    
    def _load_server_public_key(self):
        """Carica chiave pubblica del server per crittografia"""
        if not HAS_CRYPTO:
            logger.warning("cryptography not available, encryption disabled")
            return
        
        key_path = Path(self.config.server_public_key_path)
        if not key_path.exists():
            logger.warning(f"Server public key not found: {key_path}")
            return
        
        try:
            with open(key_path, "rb") as f:
                self._server_public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            logger.info("Server public key loaded for encryption")
        except Exception as e:
            logger.error(f"Failed to load server public key: {e}")
    
    async def upload_pending_data(self, pending_items: List[Dict[str, Any]]) -> bool:
        """
        Upload dati pendenti al server SFTP.
        
        Args:
            pending_items: Lista di item pendenti dalla coda
            
        Returns:
            True se upload riuscito
        """
        if not self.config.enabled:
            logger.warning("SFTP fallback not enabled")
            return False
        
        if not HAS_PARAMIKO:
            logger.error("paramiko not installed, cannot use SFTP fallback")
            return False
        
        if not pending_items:
            logger.info("No pending items to upload")
            return True
        
        try:
            # Crea dump
            encrypted_data = await self._create_encrypted_dump(pending_items)
            
            # Genera nome file
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{self.agent_id}_{timestamp}.enc"
            
            # Upload
            success = await self._upload_to_sftp(encrypted_data, filename)
            
            if success:
                logger.success(f"SFTP upload complete: {filename} ({len(pending_items)} items)")
            
            return success
            
        except Exception as e:
            logger.error(f"SFTP upload failed: {e}")
            return False
    
    async def _create_encrypted_dump(self, items: List[Dict]) -> bytes:
        """
        Crea dump crittografato dei dati.
        
        1. Serializza in JSON
        2. Comprimi con gzip
        3. Cripta con hybrid encryption (RSA + AES-GCM)
        """
        # Serializza
        dump = {
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat(),
            "item_count": len(items),
            "items": items,
        }
        json_data = json.dumps(dump, default=str).encode("utf-8")
        
        # Comprimi
        compressed = gzip.compress(json_data, compresslevel=9)
        logger.debug(f"Data compressed: {len(json_data)} -> {len(compressed)} bytes")
        
        # Cripta
        if self._server_public_key and HAS_CRYPTO:
            encrypted = self._encrypt_hybrid(compressed)
            logger.debug(f"Data encrypted: {len(compressed)} -> {len(encrypted)} bytes")
            return encrypted
        else:
            # Nessuna crittografia (non raccomandato in produzione)
            logger.warning("Uploading without encryption!")
            return compressed
    
    def _encrypt_hybrid(self, data: bytes) -> bytes:
        """
        Crittografia ibrida RSA + AES-GCM.
        
        1. Genera chiave AES casuale
        2. Cripta dati con AES-GCM
        3. Cripta chiave AES con RSA
        4. Combina: [len(enc_key)][enc_key][nonce][ciphertext]
        """
        if not HAS_CRYPTO or not self._server_public_key:
            raise RuntimeError("Encryption not available")
        
        # Genera chiave AES-256
        aes_key = os.urandom(32)  # 256 bit
        nonce = os.urandom(12)    # 96 bit per GCM
        
        # Cripta dati con AES-GCM
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Cripta chiave AES con RSA-OAEP
        encrypted_key = self._server_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combina output
        # Format: [4 bytes key length][encrypted key][12 bytes nonce][ciphertext]
        key_len = len(encrypted_key).to_bytes(4, "big")
        
        return key_len + encrypted_key + nonce + ciphertext
    
    async def _upload_to_sftp(self, data: bytes, filename: str) -> bool:
        """Upload file via SFTP"""
        return await asyncio.to_thread(self._upload_sync, data, filename)
    
    def _upload_sync(self, data: bytes, filename: str) -> bool:
        """Upload sincrono via SFTP (eseguito in thread)"""
        transport = None
        sftp = None
        
        try:
            # Connetti
            transport = paramiko.Transport((self.config.host, self.config.port))
            
            if self.config.private_key_path and Path(self.config.private_key_path).exists():
                # Autenticazione con chiave privata
                pkey = paramiko.RSAKey.from_private_key_file(self.config.private_key_path)
                transport.connect(username=self.config.username, pkey=pkey)
            elif self.config.password:
                # Autenticazione con password
                transport.connect(username=self.config.username, password=self.config.password)
            else:
                raise ValueError("No authentication method available")
            
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            # Crea directory se non esiste
            remote_dir = f"{self.config.remote_path}/{self.agent_id}"
            try:
                sftp.stat(remote_dir)
            except FileNotFoundError:
                sftp.mkdir(remote_dir)
            
            # Scrivi file
            remote_path = f"{remote_dir}/{filename}"
            
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            
            try:
                sftp.put(tmp_path, remote_path)
            finally:
                os.unlink(tmp_path)
            
            logger.info(f"Uploaded to SFTP: {remote_path} ({len(data)} bytes)")
            return True
            
        except Exception as e:
            logger.error(f"SFTP upload error: {e}")
            return False
            
        finally:
            if sftp:
                sftp.close()
            if transport:
                transport.close()
    
    async def test_connection(self) -> Dict[str, Any]:
        """Testa connessione SFTP"""
        if not self.config.enabled:
            return {"success": False, "error": "SFTP not enabled"}
        
        if not HAS_PARAMIKO:
            return {"success": False, "error": "paramiko not installed"}
        
        return await asyncio.to_thread(self._test_connection_sync)
    
    def _test_connection_sync(self) -> Dict[str, Any]:
        """Test sincrono connessione SFTP"""
        transport = None
        
        try:
            transport = paramiko.Transport((self.config.host, self.config.port))
            
            if self.config.private_key_path and Path(self.config.private_key_path).exists():
                pkey = paramiko.RSAKey.from_private_key_file(self.config.private_key_path)
                transport.connect(username=self.config.username, pkey=pkey)
            elif self.config.password:
                transport.connect(username=self.config.username, password=self.config.password)
            else:
                return {"success": False, "error": "No auth method"}
            
            return {
                "success": True,
                "host": self.config.host,
                "port": self.config.port,
                "username": self.config.username,
                "remote_path": self.config.remote_path,
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
            
        finally:
            if transport:
                transport.close()


class SFTPIngestService:
    """
    Servizio lato SERVER per processare file SFTP ricevuti.
    Da usare sul server DaDude.
    """
    
    def __init__(
        self,
        incoming_dir: str = "data/sftp_incoming",
        processed_dir: str = "data/sftp_processed",
        private_key_path: Optional[str] = None,
    ):
        self.incoming_dir = Path(incoming_dir)
        self.processed_dir = Path(processed_dir)
        self.private_key_path = private_key_path
        
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        
        # Crea directory
        self.incoming_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        
        # Carica chiave privata
        if private_key_path:
            self._load_private_key()
    
    def _load_private_key(self):
        """Carica chiave privata per decrittazione"""
        if not HAS_CRYPTO:
            return
        
        key_path = Path(self.private_key_path)
        if not key_path.exists():
            logger.warning(f"Private key not found: {key_path}")
            return
        
        try:
            with open(key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            logger.info("Private key loaded for decryption")
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
    
    async def process_incoming(self) -> List[Dict]:
        """
        Processa tutti i file nella directory incoming.
        
        Returns:
            Lista di dict con risultati processamento
        """
        results = []
        
        for enc_file in self.incoming_dir.glob("*/*.enc"):
            try:
                result = await self._process_file(enc_file)
                results.append(result)
            except Exception as e:
                logger.error(f"Error processing {enc_file}: {e}")
                results.append({
                    "file": str(enc_file),
                    "success": False,
                    "error": str(e),
                })
        
        return results
    
    async def _process_file(self, file_path: Path) -> Dict:
        """Processa singolo file crittografato"""
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        
        # Decripta
        if self._private_key and HAS_CRYPTO:
            data = self._decrypt_hybrid(encrypted_data)
        else:
            # Assume non crittografato
            data = encrypted_data
        
        # Decomprimi
        try:
            decompressed = gzip.decompress(data)
        except Exception:
            decompressed = data  # Potrebbe non essere compresso
        
        # Parse JSON
        dump = json.loads(decompressed.decode("utf-8"))
        
        # Sposta file processato
        processed_path = self.processed_dir / file_path.relative_to(self.incoming_dir)
        processed_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.rename(processed_path)
        
        return {
            "file": str(file_path),
            "success": True,
            "agent_id": dump.get("agent_id"),
            "timestamp": dump.get("timestamp"),
            "item_count": dump.get("item_count"),
            "items": dump.get("items", []),
        }
    
    def _decrypt_hybrid(self, encrypted_data: bytes) -> bytes:
        """Decrittazione ibrida RSA + AES-GCM"""
        if not HAS_CRYPTO or not self._private_key:
            raise RuntimeError("Decryption not available")
        
        # Parse formato
        key_len = int.from_bytes(encrypted_data[:4], "big")
        encrypted_key = encrypted_data[4:4+key_len]
        nonce = encrypted_data[4+key_len:4+key_len+12]
        ciphertext = encrypted_data[4+key_len+12:]
        
        # Decripta chiave AES
        aes_key = self._private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decripta dati
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext

