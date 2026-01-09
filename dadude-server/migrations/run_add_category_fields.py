#!/usr/bin/env python3
"""
Script per eseguire la migration add_category_fields
PostgreSQL ONLY - NON supporta SQLite
"""
import sys
from pathlib import Path

# Aggiungi path progetto
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import get_settings
from app.models.database import init_db
from migrations.add_category_fields import upgrade

def main():
    """Esegue la migration"""
    print("=" * 60)
    print("Migration: Aggiunge campi category, subcategory, feature, location, cespite")
    print("PostgreSQL ONLY")
    print("=" * 60)
    
    settings = get_settings()
    db_url = settings.database_url
    
    # Verifica che sia PostgreSQL
    if 'postgresql' not in db_url.lower() and 'postgres' not in db_url.lower():
        print(f"❌ ERRORE: Database URL non è PostgreSQL!")
        print(f"   URL: {db_url}")
        print(f"   Questa migration supporta SOLO PostgreSQL")
        sys.exit(1)
    
    print(f"✓ Database: PostgreSQL")
    print(f"✓ URL: {db_url.split('@')[-1] if '@' in db_url else db_url}")
    print()
    
    try:
        engine = init_db(db_url)
        
        with engine.connect() as connection:
            # Esegui migration
            upgrade(connection)
        
        print()
        print("=" * 60)
        print("✓ Migration completata con successo!")
        print("=" * 60)
        
    except Exception as e:
        print()
        print("=" * 60)
        print(f"❌ ERRORE durante la migration: {e}")
        print("=" * 60)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
