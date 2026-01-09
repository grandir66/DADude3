"""
Migration: Aggiunge campi category, subcategory, feature, location, cespite
Per PostgreSQL - NON supporta SQLite
"""
from sqlalchemy import text

def _column_exists(connection, table_name: str, column_name: str) -> bool:
    """Verifica se una colonna esiste nella tabella (PostgreSQL)"""
    result = connection.execute(text("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name = :table_name AND column_name = :column_name
        );
    """), {"table_name": table_name, "column_name": column_name})
    return result.scalar()

def _index_exists(connection, index_name: str) -> bool:
    """Verifica se un indice esiste (PostgreSQL)"""
    result = connection.execute(text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_indexes 
            WHERE indexname = :index_name
        );
    """), {"index_name": index_name})
    return result.scalar()

def upgrade(connection):
    """Aggiunge nuovi campi alla tabella inventory_devices (PostgreSQL)"""
    
    # Aggiungi subcategory
    if not _column_exists(connection, 'inventory_devices', 'subcategory'):
        connection.execute(text("""
            ALTER TABLE inventory_devices 
            ADD COLUMN subcategory VARCHAR(50) NULL;
        """))
        connection.commit()
        print("✓ Aggiunto campo subcategory")
    else:
        print("⚠ Campo subcategory già esistente")
    
    # Aggiungi feature
    if not _column_exists(connection, 'inventory_devices', 'feature'):
        connection.execute(text("""
            ALTER TABLE inventory_devices 
            ADD COLUMN feature VARCHAR(100) NULL;
        """))
        connection.commit()
        print("✓ Aggiunto campo feature")
    else:
        print("⚠ Campo feature già esistente")
    
    # Aggiungi location
    if not _column_exists(connection, 'inventory_devices', 'location'):
        connection.execute(text("""
            ALTER TABLE inventory_devices 
            ADD COLUMN location VARCHAR(255) NULL;
        """))
        connection.commit()
        print("✓ Aggiunto campo location")
    else:
        print("⚠ Campo location già esistente")
    
    # Aggiungi cespite
    if not _column_exists(connection, 'inventory_devices', 'cespite'):
        connection.execute(text("""
            ALTER TABLE inventory_devices 
            ADD COLUMN cespite VARCHAR(100) NULL;
        """))
        connection.commit()
        print("✓ Aggiunto campo cespite")
    else:
        print("⚠ Campo cespite già esistente")
    
    # Crea indici
    if not _index_exists(connection, 'idx_inventory_subcategory'):
        connection.execute(text("""
            CREATE INDEX idx_inventory_subcategory 
            ON inventory_devices(subcategory);
        """))
        connection.commit()
        print("✓ Creato indice idx_inventory_subcategory")
    else:
        print("⚠ Indice idx_inventory_subcategory già esistente")
    
    if not _index_exists(connection, 'idx_inventory_category_subcategory'):
        connection.execute(text("""
            CREATE INDEX idx_inventory_category_subcategory 
            ON inventory_devices(category, subcategory);
        """))
        connection.commit()
        print("✓ Creato indice idx_inventory_category_subcategory")
    else:
        print("⚠ Indice idx_inventory_category_subcategory già esistente")
    
    if not _index_exists(connection, 'idx_inventory_category'):
        connection.execute(text("""
            CREATE INDEX idx_inventory_category 
            ON inventory_devices(category);
        """))
        connection.commit()
        print("✓ Creato indice idx_inventory_category")
    else:
        print("⚠ Indice idx_inventory_category già esistente")


def downgrade(connection):
    """Rimuove i campi aggiunti (PostgreSQL)"""
    try:
        # PostgreSQL supporta IF EXISTS per DROP
        connection.execute(text("DROP INDEX IF EXISTS idx_inventory_category_subcategory;"))
        connection.execute(text("DROP INDEX IF EXISTS idx_inventory_subcategory;"))
        connection.execute(text("DROP INDEX IF EXISTS idx_inventory_category;"))
        connection.execute(text("ALTER TABLE inventory_devices DROP COLUMN IF EXISTS subcategory;"))
        connection.execute(text("ALTER TABLE inventory_devices DROP COLUMN IF EXISTS feature;"))
        connection.execute(text("ALTER TABLE inventory_devices DROP COLUMN IF EXISTS location;"))
        connection.execute(text("ALTER TABLE inventory_devices DROP COLUMN IF EXISTS cespite;"))
        connection.commit()
        print("✓ Rimossi campi e indici")
    except Exception as e:
        print(f"⚠ Errore durante downgrade: {e}")
        connection.rollback()
