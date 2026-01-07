"""
DaDude - Encryption Service
Gestione crittografia per dati sensibili (password, API keys, etc.)
"""
import os
import base64
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from loguru import logger

from ..config import get_settings


class EncryptionService:
    """
    Servizio per crittografia/decrittografia dati sensibili.
    Usa Fernet (AES-128-CBC) con chiave derivata da master key.
    """
    
    def __init__(self, master_key: Optional[str] = None):
        """
        Inizializza il servizio di encryption.
        
        Args:
            master_key: Chiave master per derivazione. Se None, usa ENCRYPTION_KEY da env.
        """
        self._fernet: Optional[Fernet] = None
        self._initialize(master_key)
    
    def _initialize(self, master_key: Optional[str] = None):
        """Inizializza Fernet con chiave derivata"""
        settings = get_settings()
        
        # Ottieni master key da parametro o environment
        key = master_key or getattr(settings, 'encryption_key', None)
        
        if not key:
            # Genera chiave se non esiste e salvala
            key = self._generate_and_save_key()
        
        # Deriva chiave Fernet dalla master key
        self._fernet = self._derive_fernet_key(key)
        logger.debug("Encryption service initialized")
    
    def _generate_and_save_key(self) -> str:
        """Genera nuova chiave e la salva in file"""
        key = Fernet.generate_key().decode()
        
        # Salva in file .encryption_key
        key_file = "./data/.encryption_key"
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        
        # Controlla se esiste già
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                key = f.read().strip()
            logger.debug("Loaded existing encryption key")
        else:
            with open(key_file, 'w') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Solo owner può leggere
            logger.info("Generated new encryption key")
        
        return key
    
    def _derive_fernet_key(self, master_key: str) -> Fernet:
        """Deriva chiave Fernet dalla master key usando PBKDF2"""
        # Salt fisso (in produzione usare salt random per-record)
        salt = b'dadude_salt_v1_2024'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        return Fernet(key)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Cripta una stringa.
        
        Args:
            plaintext: Testo in chiaro da criptare
            
        Returns:
            Testo criptato in base64
        """
        if not plaintext:
            return ""
        
        if not self._fernet:
            raise RuntimeError("Encryption service not initialized")
        
        encrypted = self._fernet.encrypt(plaintext.encode())
        return encrypted.decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decripta una stringa.
        
        Args:
            ciphertext: Testo criptato in base64
            
        Returns:
            Testo in chiaro
        """
        if not ciphertext:
            return ""
        
        if not self._fernet:
            raise RuntimeError("Encryption service not initialized")
        
        try:
            decrypted = self._fernet.decrypt(ciphertext.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            # Potrebbe essere un valore non criptato (migrazione)
            return ciphertext
    
    def is_encrypted(self, value: str) -> bool:
        """Verifica se un valore sembra essere criptato"""
        if not value:
            return False
        try:
            # I valori Fernet iniziano con 'gAAAAA'
            return value.startswith('gAAAAA') and len(value) > 50
        except:
            return False
    
    def encrypt_if_needed(self, value: str) -> str:
        """Cripta solo se non già criptato"""
        if not value or self.is_encrypted(value):
            return value
        return self.encrypt(value)
    
    def decrypt_if_needed(self, value: str) -> str:
        """Decripta solo se criptato"""
        if not value or not self.is_encrypted(value):
            return value
        return self.decrypt(value)


# Singleton
_encryption_service: Optional[EncryptionService] = None


def get_encryption_service() -> EncryptionService:
    """Get singleton EncryptionService instance"""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service


# Utility functions
def encrypt_password(password: str) -> str:
    """Utility per criptare password"""
    return get_encryption_service().encrypt(password)


def decrypt_password(encrypted: str) -> str:
    """Utility per decriptare password"""
    return get_encryption_service().decrypt(encrypted)
