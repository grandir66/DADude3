"""
DaDude - Dude Agent Sync Service
Sincronizzazione agent da The Dude server
"""
from typing import Optional, List, Dict, Any
from loguru import logger
from datetime import datetime

from .dude_service import get_dude_service
from ..models.database import init_db, get_session
from ..models.inventory import DudeAgent
from ..config import get_settings


class DudeAgentSyncService:
    """
    Servizio per sincronizzare agent dal server The Dude.
    Gli agent sono router MikroTik con il pacchetto Dude installato
    che si connettono automaticamente al server.
    """
    
    def __init__(self):
        self._last_sync: Optional[datetime] = None
    
    def sync_agents(self) -> Dict[str, Any]:
        """
        Sincronizza agent dal server The Dude al database locale.
        """
        try:
            dude = get_dude_service()
            
            # Ottieni agent dal server Dude
            agents = dude.get_agents()
            
            if not agents:
                return {
                    "success": True,
                    "synced": 0,
                    "message": "Nessun agent trovato su The Dude",
                }
            
            # Connetti al database locale
            settings = get_settings()
            db_url = settings.database_url
            engine = init_db(db_url)
            session = get_session(engine)
            
            synced = 0
            created = 0
            updated = 0
            
            try:
                for agent in agents:
                    dude_id = agent.get("id", "")
                    if not dude_id:
                        continue
                    
                    # Cerca agent esistente
                    existing = session.query(DudeAgent).filter(
                        DudeAgent.dude_id == dude_id
                    ).first()
                    
                    if existing:
                        # Aggiorna
                        existing.name = agent.get("name", "Unknown")
                        existing.address = agent.get("address", "")
                        existing.status = agent.get("status", "unknown")
                        existing.version = agent.get("version", "")
                        existing.last_seen = datetime.now()
                        updated += 1
                    else:
                        # Crea nuovo
                        new_agent = DudeAgent(
                            dude_id=dude_id,
                            name=agent.get("name", "Unknown"),
                            address=agent.get("address", ""),
                            status=agent.get("status", "unknown"),
                            version=agent.get("version", ""),
                            last_seen=datetime.now(),
                        )
                        session.add(new_agent)
                        created += 1
                    
                    synced += 1
                
                session.commit()
                self._last_sync = datetime.now()
                
                return {
                    "success": True,
                    "synced": synced,
                    "created": created,
                    "updated": updated,
                    "message": f"Sincronizzati {synced} agent ({created} nuovi, {updated} aggiornati)",
                }
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error syncing agents: {e}")
            return {
                "success": False,
                "error": str(e),
            }
    
    def list_agents(self, customer_id: str = None) -> List[Dict[str, Any]]:
        """
        Lista agent sincronizzati.
        Se customer_id specificato, filtra per cliente.
        """
        settings = get_settings()
        db_url = settings.database_url
        engine = init_db(db_url)
        session = get_session(engine)
        
        try:
            query = session.query(DudeAgent)
            
            if customer_id:
                query = query.filter(DudeAgent.customer_id == customer_id)
            
            agents = query.order_by(DudeAgent.name).all()
            
            return [
                {
                    "id": a.id,
                    "dude_id": a.dude_id,
                    "name": a.name,
                    "address": a.address,
                    "status": a.status,
                    "version": a.version,
                    "customer_id": a.customer_id,
                    "agent_assignment_id": a.agent_assignment_id,
                    "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                }
                for a in agents
            ]
            
        finally:
            session.close()
    
    def assign_to_customer(
        self,
        dude_agent_id: str,  # ID locale, non dude_id
        customer_id: str,
    ) -> Dict[str, Any]:
        """Associa un agent Dude a un cliente"""
        settings = get_settings()
        db_url = settings.database_url
        engine = init_db(db_url)
        session = get_session(engine)
        
        try:
            agent = session.query(DudeAgent).filter(
                DudeAgent.id == dude_agent_id
            ).first()
            
            if not agent:
                return {"success": False, "error": "Agent non trovato"}
            
            agent.customer_id = customer_id
            session.commit()
            
            return {
                "success": True,
                "message": f"Agent {agent.name} associato al cliente {customer_id}",
            }
            
        finally:
            session.close()
    
    def unassign_from_customer(self, dude_agent_id: str) -> Dict[str, Any]:
        """Rimuove associazione agent-cliente"""
        settings = get_settings()
        db_url = settings.database_url
        engine = init_db(db_url)
        session = get_session(engine)
        
        try:
            agent = session.query(DudeAgent).filter(
                DudeAgent.id == dude_agent_id
            ).first()
            
            if not agent:
                return {"success": False, "error": "Agent non trovato"}
            
            agent.customer_id = None
            session.commit()
            
            return {
                "success": True,
                "message": f"Agent {agent.name} rimosso dal cliente",
            }
            
        finally:
            session.close()
    
    def get_available_agents(self) -> List[Dict[str, Any]]:
        """Ottiene agent non ancora associati a clienti"""
        settings = get_settings()
        db_url = settings.database_url
        engine = init_db(db_url)
        session = get_session(engine)
        
        try:
            agents = session.query(DudeAgent).filter(
                DudeAgent.customer_id.is_(None)
            ).order_by(DudeAgent.name).all()
            
            return [
                {
                    "id": a.id,
                    "dude_id": a.dude_id,
                    "name": a.name,
                    "address": a.address,
                    "status": a.status,
                    "version": a.version,
                }
                for a in agents
            ]
            
        finally:
            session.close()


# Singleton
_sync_service: Optional[DudeAgentSyncService] = None


def get_dude_agent_sync_service() -> DudeAgentSyncService:
    global _sync_service
    if _sync_service is None:
        _sync_service = DudeAgentSyncService()
    return _sync_service
