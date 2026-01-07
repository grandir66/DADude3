"""
DaDude Agent - Fallback Module
Gestione fallback SFTP quando server irraggiungibile
"""
from .sftp_uploader import SFTPFallbackUploader, SFTPConfig

__all__ = ["SFTPFallbackUploader", "SFTPConfig"]

