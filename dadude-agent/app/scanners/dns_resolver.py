"""
DaDude Agent - DNS Resolver
Risoluzione nomi DNS forward e reverse
"""
import asyncio
from typing import List, Dict, Optional
from loguru import logger


async def reverse_lookup(
    target: str,
    dns_server: Optional[str] = None,
) -> Optional[str]:
    """
    Esegue reverse DNS lookup per un singolo IP.
    
    Returns:
        Hostname o None se non trovato
    """
    loop = asyncio.get_event_loop()
    
    def lookup():
        try:
            import dns.resolver
            import dns.reversename
            
            rev_name = dns.reversename.from_address(target)
            
            resolver = dns.resolver.Resolver()
            if dns_server:
                resolver.nameservers = [dns_server]
            resolver.timeout = 2
            resolver.lifetime = 3
            
            answers = resolver.resolve(rev_name, 'PTR')
            for rdata in answers:
                hostname = str(rdata).rstrip('.')
                return hostname
            
            return None
            
        except Exception as e:
            logger.debug(f"Reverse DNS failed for {target}: {e}")
            return None
    
    return await loop.run_in_executor(None, lookup)


async def batch_reverse_lookup(
    targets: List[str],
    dns_server: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    """
    Esegue reverse DNS lookup per una lista di IP.
    
    Returns:
        Dict[IP -> hostname] (hostname può essere None)
    """
    logger.debug(f"Batch reverse DNS for {len(targets)} targets (DNS: {dns_server or 'system'})")
    
    async def lookup_one(ip: str) -> tuple:
        hostname = await reverse_lookup(ip, dns_server)
        return (ip, hostname)
    
    # Esegui in parallelo
    tasks = [lookup_one(ip) for ip in targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    output = {}
    for result in results:
        if isinstance(result, tuple):
            ip, hostname = result
            output[ip] = hostname
    
    resolved = sum(1 for v in output.values() if v)
    logger.info(f"Batch DNS complete: {resolved}/{len(targets)} resolved")
    
    return output


async def forward_lookup(
    hostname: str,
    dns_server: Optional[str] = None,
) -> Optional[str]:
    """
    Esegue forward DNS lookup per un hostname.
    
    Returns:
        IP o None se non trovato
    """
    loop = asyncio.get_event_loop()
    
    def lookup():
        try:
            import dns.resolver
            
            resolver = dns.resolver.Resolver()
            if dns_server:
                resolver.nameservers = [dns_server]
            resolver.timeout = 2
            resolver.lifetime = 3
            
            answers = resolver.resolve(hostname, 'A')
            for rdata in answers:
                return str(rdata)
            
            return None
            
        except Exception as e:
            logger.debug(f"Forward DNS failed for {hostname}: {e}")
            return None
    
    return await loop.run_in_executor(None, lookup)

