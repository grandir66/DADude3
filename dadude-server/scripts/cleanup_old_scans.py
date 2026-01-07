#!/usr/bin/env python3
"""
Script per pulire scansioni vecchie dal database
Mantiene solo le ultime 5 scansioni completate per ogni rete
"""
import sys
import os

# Aggiungi il path del progetto
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.database import ScanResult, Network, init_db, get_session
from app.config import get_settings
from sqlalchemy import desc
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def cleanup_old_scans(keep_count: int = 5, customer_id: str = None):
    """
    Pulisce scansioni vecchie mantenendo solo le ultime N per ogni rete.
    
    Args:
        keep_count: Numero di scansioni da mantenere per rete (default: 5)
        customer_id: ID cliente specifico (None per tutti i clienti)
    """
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        # Trova tutte le reti
        if customer_id:
            networks = session.query(Network).filter(
                Network.customer_id == customer_id
            ).all()
        else:
            networks = session.query(Network).all()
        
        total_deleted = 0
        networks_cleaned = []
        
        logger.info(f"Starting cleanup: {len(networks)} networks to process")
        
        for network in networks:
            # Trova tutte le scansioni completate per questa rete
            all_scans = session.query(ScanResult).filter(
                ScanResult.network_id == network.id,
                ScanResult.status == "completed"
            ).order_by(desc(ScanResult.created_at)).all()
            
            # Mantieni solo le ultime N, elimina le altre
            if len(all_scans) > keep_count:
                scans_to_delete = all_scans[keep_count:]
                deleted_count = 0
                for old_scan in scans_to_delete:
                    # I DiscoveredDevice verranno eliminati automaticamente per cascade
                    session.delete(old_scan)
                    deleted_count += 1
                
                if deleted_count > 0:
                    total_deleted += deleted_count
                    networks_cleaned.append({
                        "network_id": network.id,
                        "network_name": network.name,
                        "network_cidr": network.ip_network,
                        "customer_id": network.customer_id,
                        "deleted_count": deleted_count,
                        "kept_count": keep_count,
                        "total_scans": len(all_scans)
                    })
                    logger.info(f"Network {network.name} ({network.ip_network}): deleting {deleted_count} old scans, keeping {keep_count}")
        
        if total_deleted > 0:
            session.commit()
            logger.info(f"\n{'='*60}")
            logger.info(f"Cleanup completed!")
            logger.info(f"Total deleted: {total_deleted} scans")
            logger.info(f"Networks cleaned: {len(networks_cleaned)}")
            logger.info(f"{'='*60}\n")
            
            # Dettagli per rete
            for net_info in networks_cleaned:
                logger.info(f"  - {net_info['network_name']} ({net_info['network_cidr']}): "
                          f"deleted {net_info['deleted_count']}, kept {net_info['kept_count']} "
                          f"(total was {net_info['total_scans']})")
        else:
            logger.info("No old scans to clean up - all networks already have <= 5 scans")
        
        return {
            "total_deleted": total_deleted,
            "networks_cleaned": networks_cleaned
        }
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error cleaning up old scans: {e}", exc_info=True)
        raise
    finally:
        session.close()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Cleanup old scan results")
    parser.add_argument("--keep", type=int, default=5, help="Number of scans to keep per network (default: 5)")
    parser.add_argument("--customer-id", type=str, default=None, help="Specific customer ID (optional)")
    
    args = parser.parse_args()
    
    logger.info(f"Starting cleanup: keeping last {args.keep} scans per network")
    if args.customer_id:
        logger.info(f"Customer filter: {args.customer_id}")
    
    try:
        result = cleanup_old_scans(keep_count=args.keep, customer_id=args.customer_id)
        logger.info("Cleanup completed successfully!")
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        sys.exit(1)

