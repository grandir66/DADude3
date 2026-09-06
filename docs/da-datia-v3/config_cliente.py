#!/usr/bin/env python3
"""
config_cliente.py - Questionario CLI per generare CONFIG_CLIENTI.md
Zero dipendenze esterne, solo stdlib Python 3.
"""

import json
import re
import sys
import unicodedata
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent


# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

def ask(prompt: str, default: str = "") -> str:
    display = f"{prompt} [{default}]: " if default else f"{prompt}: "
    try:
        value = input(display).strip()
    except EOFError:
        return default
    return value if value else default


def ask_yn(prompt: str, default: bool = False) -> bool:
    hint = "[S/n]" if default else "[s/N]"
    try:
        answer = input(f"{prompt} {hint}: ").strip().lower()
    except EOFError:
        return default
    if answer in ("s", "si", "y", "yes"):
        return True
    if answer in ("n", "no"):
        return False
    return default


def ask_credenziali(prompt_prefix: str = "", existing: str = "",
                    utente_prefix: str = "") -> str:
    """Chiede utente e password separatamente e restituisce 'utente / password'.

    utente_prefix: stringa preposta al default del campo Utente quando non
                   esiste un valore salvato (es. 'AZIENDA\\' per AD).
    """
    p = f"{prompt_prefix} " if prompt_prefix else ""
    # Scomponi il valore esistente nel formato 'utente / password'
    utente_def = pwd_def = ""
    if existing and " / " in existing:
        utente_def, pwd_def = existing.split(" / ", 1)
        utente_def = utente_def.strip()
        pwd_def    = pwd_def.strip()
    elif existing:
        utente_def = existing  # compatibilità con vecchi file

    # Usa il prefisso solo se non c'è già un valore salvato per l'utente
    if not utente_def and utente_prefix:
        utente_def = utente_prefix

    utente = ask(f"{p}Utente", utente_def)
    pwd    = ask(f"{p}Password", pwd_def)
    if utente and pwd:
        return f"{utente} / {pwd}"
    return utente or pwd or ""


def section_header(title: str) -> None:
    line = "═" * 44
    print(f"\n{line}")
    print(f"  {title}")
    print(f"{line}")


def add_another(label: str) -> bool:
    return ask_yn(f"Vuoi aggiungere un altro/a {label}?", default=False)


def sanitize_filename(s: str) -> str:
    s = unicodedata.normalize("NFD", s)
    s = s.encode("ascii", "ignore").decode("ascii")
    s = s.replace(" ", "_")
    s = re.sub(r"[^\w\-]", "", s)
    s = re.sub(r"_+", "_", s)
    return s[:80].strip("_")


def collect_multiline(prompt: str, default: str = "") -> str:
    if default:
        print(f"{prompt} (riga vuota per terminare, testo attuale sotto):")
        print(default)
        print("--- Riscrivi o premi Invio su riga vuota per mantenere ---")
    else:
        print(f"{prompt} (riga vuota per terminare):")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "":
            break
        lines.append(line)
    result = "\n".join(lines)
    return result if result else default


# ─────────────────────────────────────────────
# JSON PERSISTENCE
# ─────────────────────────────────────────────

def save_json(data: dict, path: Path) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pick_existing() -> dict | None:
    """Cerca file .json salvati e offre di caricarne uno. Restituisce i dati o None."""
    files = sorted(OUTPUT_DIR.glob("**/*.json"))
    if not files:
        return None

    section_header("FILE ESISTENTI")
    print("  Trovati i seguenti file salvati:\n")
    for i, f in enumerate(files, 1):
        print(f"  {i}) {f.name}")
    print(f"  0) Crea nuovo cliente")
    print()

    while True:
        try:
            raw = input("  Scegli (0 per nuovo): ").strip()
        except EOFError:
            return None
        if raw == "0" or raw == "":
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(files):
            chosen = files[int(raw) - 1]
            try:
                data = load_json(chosen)
                print(f"\n  Caricato: {chosen.name}")
                return data
            except Exception as e:
                print(f"  Errore nel caricamento: {e}")
                return None
        print(f"  Inserisci un numero tra 0 e {len(files)}.")


# ─────────────────────────────────────────────
# COLLECT FUNCTIONS
# Ogni funzione accetta un parametro `existing` con i dati precedenti.
# I valori esistenti appaiono come default — Invio per confermare.
# ─────────────────────────────────────────────

def collect_list_section(title: str, label: str, fields: list, existing: list) -> list:
    """
    Raccoglitore generico per sezioni con righe ripetibili.
    fields: lista di (chiave, prompt, default_fn) dove default_fn(row) -> str
    """
    section_header(title)
    rows = []
    # Presenta elementi esistenti con defaults pre-compilati
    for ex in existing:
        n = len(rows) + 1
        print(f"\n  {label} {n}")
        row = {}
        for key, prompt, default_fn in fields:
            row[key] = ask(prompt, default_fn(ex))
        rows.append(row)
    # Chiedi se aggiungere altri (o avvia il loop se lista vuota)
    if rows and not add_another(label):
        return rows
    while True:
        n = len(rows) + 1
        print(f"\n  {label} {n}")
        row = {}
        for key, prompt, default_fn in fields:
            row[key] = ask(prompt, "")
        rows.append(row)
        if not add_another(label):
            break
    return rows


def collect_cliente(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("DATI CLIENTE")
    return {
        "cliente":     ask("Nome cliente",       ex.get("cliente", "")),
        "referente":   ask("Referente/i tecnico", ex.get("referente", "")),
        "cod_cliente": ask("Codice cliente",      ex.get("cod_cliente", "")),
    }


def collect_accesso(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("ACCESSO SERVIZI CLIENTE")

    # RDP
    rdp_list = []
    for prev in ex.get("rdp", []):
        rdp_list.append(ask(f"  RDP {len(rdp_list)+1} (indirizzo/note)", prev))
    if rdp_list and not add_another("RDP"):
        pass
    else:
        while True:
            rdp_list.append(ask(f"  RDP {len(rdp_list)+1} (indirizzo/note)"))
            if not add_another("RDP"):
                break

    # TeamViewer
    tv_list = []
    for prev in ex.get("teamviewer", []):
        tv_list.append(ask(f"  TeamViewer {len(tv_list)+1} (ID/note)", prev))
    if tv_list and not add_another("TeamViewer"):
        pass
    else:
        while True:
            tv_list.append(ask(f"  TeamViewer {len(tv_list)+1} (ID/note)"))
            if not add_another("TeamViewer"):
                break

    # VPN (opzionale)
    vpn_list = ex.get("vpn", [])
    had_vpn = bool(vpn_list)
    if ask_yn("  Vuoi aggiungere/modificare VPN?", default=had_vpn):
        new_vpn = []
        for prev in vpn_list:
            new_vpn.append(ask(f"  VPN {len(new_vpn)+1} (note)", prev))
        if new_vpn and not add_another("VPN"):
            vpn_list = new_vpn
        else:
            while True:
                new_vpn.append(ask(f"  VPN {len(new_vpn)+1} (note)"))
                if not add_another("VPN"):
                    break
            vpn_list = new_vpn
    else:
        vpn_list = []

    # Bitwise (opzionale)
    prev_bitwise = ex.get("bitwise", "")
    if ask_yn("  Vuoi aggiungere/modificare Bitwise?", default=bool(prev_bitwise)):
        bitwise = ask("  Bitwise (note)", prev_bitwise)
    else:
        bitwise = ""

    return {"rdp": rdp_list, "teamviewer": tv_list, "vpn": vpn_list, "bitwise": bitwise}


def collect_network(existing: list = None) -> list:
    return collect_list_section(
        title="NETWORK", label="VLAN",
        fields=[
            ("id",     "  ID VLAN",  lambda r: r.get("id", "")),
            ("subnet", "  Subnet",   lambda r: r.get("subnet", "")),
            ("gtw",    "  Gateway",  lambda r: r.get("gtw", "")),
            ("dns",    "  DNS",      lambda r: r.get("dns", "")),
            ("note",   "  Note",     lambda r: r.get("note", "")),
        ],
        existing=existing or [],
    )


def collect_switch(existing: list = None) -> list:
    section_header("SWITCH")
    rows = []
    ex_list = existing or []
    for ex in ex_list:
        n = len(rows) + 1
        print(f"\n  Switch {n}")
        rows.append({
            "nome":        ask("  Nome switch",    ex.get("nome", f"SW{n:02d}")),
            "ip":          ask("  IP",             ex.get("ip", "")),
            "modello":     ask("  Modello",        ex.get("modello", "")),
            "credenziali": ask_credenziali("  ",   ex.get("credenziali", "")),
            "snmp":        ask("  SNMP community", ex.get("snmp", "")),
            "note":        ask("  Note",           ex.get("note", "")),
        })
    if rows and not add_another("switch"):
        return rows
    while True:
        n = len(rows) + 1
        print(f"\n  Switch {n}")
        rows.append({
            "nome":        ask("  Nome switch", f"SW{n:02d}"),
            "ip":          ask("  IP"),
            "modello":     ask("  Modello"),
            "credenziali": ask_credenziali("  "),
            "snmp":        ask("  SNMP community"),
            "note":        ask("  Note"),
        })
        if not add_another("switch"):
            break
    return rows


def collect_firewall(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("FIREWALL")
    return {
        "modello":     ask("Modello",       ex.get("modello", "")),
        "sn":          ask("Serial Number", ex.get("sn", "")),
        "ip_interno":  ask("IP Interno",    ex.get("ip_interno", "")),
        "ip_esterno":  ask("IP Esterno",    ex.get("ip_esterno", "")),
        "credenziali": ask_credenziali("",  ex.get("credenziali", "")),
        "snmp":        ask("SNMP",          ex.get("snmp", "")),
        "note":        ask("Note",          ex.get("note", "")),
    }


def collect_linee(existing: list = None) -> list:
    section_header("LINEE DATI")
    rows = []
    ex_list = existing or []
    for ex in ex_list:
        n = len(rows) + 1
        print(f"\n  Linea {n}")
        rows.append({
            "nome":     ask("  Nome linea", ex.get("nome", f"Linea_{n}")),
            "provider": ask("  Provider",   ex.get("provider", "")),
            "ip_sub":   ask("  IP/Subnet",  ex.get("ip_sub", "")),
            "ip_p2p":   ask("  IP p2p",     ex.get("ip_p2p", "")),
            "router":   ask("  Router",     ex.get("router", "")),
            "note":     ask("  Note",       ex.get("note", "")),
        })
    if rows and not add_another("linea dati"):
        return rows
    while True:
        n = len(rows) + 1
        print(f"\n  Linea {n}")
        rows.append({
            "nome":     ask("  Nome linea", f"Linea_{n}"),
            "provider": ask("  Provider"),
            "ip_sub":   ask("  IP/Subnet"),
            "ip_p2p":   ask("  IP p2p"),
            "router":   ask("  Router"),
            "note":     ask("  Note"),
        })
        if not add_another("linea dati"):
            break
    return rows


def collect_wifi(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("WIFI")
    d: dict = {
        "controller":      ask("WiFi Controller",              ex.get("controller", "")),
        "controller_ip":   ask("IP Controller",               ex.get("controller_ip", "")),
        "controller_cred": ask_credenziali("Controller",      ex.get("controller_cred", "")),
        "aps": [],
        "ssids": [],
        "note": "",
    }
    # APs
    print("\n  Access Point:")
    for prev in ex.get("aps", []):
        n = len(d["aps"]) + 1
        d["aps"].append(ask(f"  AP{n:02d} nome/IP", prev))
    if d["aps"] and not add_another("AP"):
        pass
    else:
        while True:
            n = len(d["aps"]) + 1
            d["aps"].append(ask(f"  AP{n:02d} nome/IP"))
            if not add_another("AP"):
                break
    # SSIDs
    print("\n  SSID:")
    for prev in ex.get("ssids", []):
        n = len(d["ssids"]) + 1
        ssid = ask(f"  SSID{n} nome", prev.get("ssid", ""))
        wpa  = ask(f"  SSID{n} WPA key", prev.get("wpa", ""))
        d["ssids"].append({"ssid": ssid, "wpa": wpa})
    if d["ssids"] and not add_another("SSID"):
        pass
    else:
        while True:
            n = len(d["ssids"]) + 1
            ssid = ask(f"  SSID{n} nome")
            wpa  = ask(f"  SSID{n} WPA key")
            d["ssids"].append({"ssid": ssid, "wpa": wpa})
            if not add_another("SSID"):
                break
    d["note"] = ask("Note", ex.get("note", ""))
    return d


def collect_vpn(existing: list = None) -> list:
    return collect_list_section(
        title="VPN", label="tunnel VPN",
        fields=[
            ("nome",          "  Nome VPN",        lambda r: r.get("nome", "")),
            ("local_device",  "  Local Device",    lambda r: r.get("local_device", "")),
            ("remote_device", "  Remote Device",   lambda r: r.get("remote_device", "")),
            ("local_ip",      "  Local IP",        lambda r: r.get("local_ip", "")),
            ("remote_ip",     "  Remote IP",       lambda r: r.get("remote_ip", "")),
            ("local_net",     "  Local Network",   lambda r: r.get("local_net", "")),
            ("remote_net",    "  Remote Network",  lambda r: r.get("remote_net", "")),
            ("ike",           "  IKE parameters",  lambda r: r.get("ike", "")),
            ("ipsec",         "  IPSEC parameters",lambda r: r.get("ipsec", "")),
            ("note",          "  Note",            lambda r: r.get("note", "")),
        ],
        existing=existing or [],
    )


def collect_storage(existing: list = None) -> list:
    section_header("STORAGE")
    rows = []
    ex_list = existing or []
    for ex in ex_list:
        n = len(rows) + 1
        print(f"\n  NAS {n}")
        rows.append({
            "nome":        ask("  Nome NAS",      ex.get("nome", f"NAS {n}")),
            "modello":     ask("  Modello",       ex.get("modello", "")),
            "ip":          ask("  IP",            ex.get("ip", "")),
            "credenziali": ask_credenziali("  ",  ex.get("credenziali", "")),
            "spazio":      ask("  Spazio totale", ex.get("spazio", "")),
            "snmp":        ask("  SNMP",          ex.get("snmp", "")),
            "note":        ask("  Note",          ex.get("note", "")),
        })
    if rows and not add_another("NAS"):
        return rows
    while True:
        n = len(rows) + 1
        print(f"\n  NAS {n}")
        rows.append({
            "nome":        ask("  Nome NAS", f"NAS {n}"),
            "modello":     ask("  Modello"),
            "ip":          ask("  IP"),
            "credenziali": ask_credenziali("  "),
            "spazio":      ask("  Spazio totale"),
            "snmp":        ask("  SNMP"),
            "note":        ask("  Note"),
        })
        if not add_another("NAS"):
            break
    return rows


def collect_ad(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("AD (Active Directory)")
    # Compatibilità con vecchi JSON che avevano un unico campo "dominio"
    dominio_dns_def     = ex.get("dominio_dns",     ex.get("dominio", ""))
    dominio_netbios_def = ex.get("dominio_netbios", "")

    dominio_dns     = ask("Dominio DNS (FQDN)",    dominio_dns_def)
    dominio_netbios = ask("Dominio NETBIOS",        dominio_netbios_def)

    # Default utente: NETBIOS\  (solo se non c'è già un valore salvato)
    utente_prefix = f"{dominio_netbios}\\" if dominio_netbios else ""

    return {
        "dominio_dns":     dominio_dns,
        "dominio_netbios": dominio_netbios,
        "credenziali":     ask_credenziali("", ex.get("credenziali", ""),
                                           utente_prefix=utente_prefix),
        "dns":             ask("DNS",              ex.get("dns", "")),
        "dhcp":            ask("DHCP",             ex.get("dhcp", "")),
        "user_domarc":     ask("User DOMARC",      ex.get("user_domarc", "")),
        "dc":              ask("Domain Controller",ex.get("dc", "")),
        "note":            ask("Note",             ex.get("note", "")),
    }


def collect_server_fisici(existing: list = None) -> list:
    section_header("SERVER FISICI")
    rows = []
    ex_list = existing or []
    for ex in ex_list:
        n = len(rows) + 1
        print(f"\n  Server {n}")
        rows.append({
            "nome":        ask("  Nome server",       ex.get("nome", "")),
            "modello":     ask("  Modello",           ex.get("modello", "")),
            "ip":          ask("  IP",                ex.get("ip", "")),
            "ip_ilo":      ask("  IP iLO/IPMI",       ex.get("ip_ilo", "")),
            "credenziali": ask_credenziali("  ",      ex.get("credenziali", "")),
            "snmp":        ask("  SNMP",              ex.get("snmp", "")),
            "note":        ask("  Note (SN, Anno...)",ex.get("note", "")),
        })
    if rows and not add_another("server fisico"):
        return rows
    while True:
        n = len(rows) + 1
        print(f"\n  Server {n}")
        rows.append({
            "nome":        ask("  Nome server"),
            "modello":     ask("  Modello"),
            "ip":          ask("  IP"),
            "ip_ilo":      ask("  IP iLO/IPMI"),
            "credenziali": ask_credenziali("  "),
            "snmp":        ask("  SNMP"),
            "note":        ask("  Note (SN, Anno...)"),
        })
        if not add_another("server fisico"):
            break
    return rows


def _pick_virt_tipo(existing_tipo: str) -> str:
    """Mostra un menu e restituisce 'vmware' o 'proxmox'."""
    OPZIONI = {"1": "vmware", "2": "proxmox"}
    LABELS  = {"vmware": "VMware", "proxmox": "Proxmox"}
    print("\n  Piattaforma di virtualizzazione:")
    print("  1) VMware")
    print("  2) Proxmox")
    default_num = "1" if existing_tipo != "proxmox" else "2"
    while True:
        try:
            scelta = input(f"  Scelta [{default_num}]: ").strip()
        except EOFError:
            return OPZIONI[default_num]
        if scelta == "":
            return OPZIONI[default_num]
        if scelta in OPZIONI:
            return OPZIONI[scelta]
        print(f"  Inserisci 1 o 2.")


def _collect_vmware(ex: dict) -> dict:
    """Raccoglie i dati VMware (vCenter + ESX hosts)."""
    d: dict = {
        "tipo":              "vmware",
        "vcenter_ver":       ask("  Versione vCenter",           ex.get("vcenter_ver", "")),
        "vcenter_ip":        ask("  IP vCenter",                 ex.get("vcenter_ip", "")),
        "vcenter_cred":      ask_credenziali("  vCenter",        ex.get("vcenter_cred", "")),
        "vcenter_cred_5480": ask_credenziali("  vCenter (5480)", ex.get("vcenter_cred_5480", "")),
        "esx": [],
    }
    print("\n  ESX Hosts:")
    for prev in ex.get("esx", []):
        n = len(d["esx"]) + 1
        d["esx"].append(ask(f"  ESX{n:02d} nome/IP", prev))
    if d["esx"] and not add_another("ESX host"):
        return d
    while True:
        n = len(d["esx"]) + 1
        d["esx"].append(ask(f"  ESX{n:02d} nome/IP"))
        if not add_another("ESX host"):
            break
    return d


def _collect_proxmox(ex: dict) -> dict:
    """Raccoglie i dati Proxmox (cluster opzionale + nodi)."""
    d: dict = {
        "tipo":    "proxmox",
        "versione": ask("  Versione PVE (es. 8.2)", ex.get("versione", "")),
        "cluster":  ask("  Nome cluster (vuoto se standalone)", ex.get("cluster", "")),
        "nodi":     [],
        "note":     "",
    }
    print("\n  Nodi Proxmox:")
    for prev in ex.get("nodi", []):
        n = len(d["nodi"]) + 1
        print(f"\n  Nodo {n}")
        d["nodi"].append({
            "nome":        ask("  Nome nodo",  prev.get("nome", "")),
            "ip":          ask("  IP",         prev.get("ip", "")),
            "credenziali": ask_credenziali("  ", prev.get("credenziali", "")),
        })
    if d["nodi"] and not add_another("nodo"):
        pass
    else:
        while True:
            n = len(d["nodi"]) + 1
            print(f"\n  Nodo {n}")
            d["nodi"].append({
                "nome":        ask("  Nome nodo"),
                "ip":          ask("  IP"),
                "credenziali": ask_credenziali("  "),
            })
            if not add_another("nodo"):
                break
    d["note"] = ask("  Note", ex.get("note", ""))
    return d


def collect_virtualizzazione(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("VIRTUALIZZAZIONE")
    tipo = _pick_virt_tipo(ex.get("tipo", "vmware"))
    if tipo == "proxmox":
        return _collect_proxmox(ex if ex.get("tipo") == "proxmox" else {})
    else:
        return _collect_vmware(ex if ex.get("tipo") != "proxmox" else {})


def collect_vm(existing: list = None) -> list:
    return collect_list_section(
        title="VM", label="VM",
        fields=[
            ("nome",     "  Nome VM",                    lambda r: r.get("nome", "")),
            ("ip",       "  IP",                         lambda r: r.get("ip", "")),
            ("funzioni", "  Funzioni (es. AD, DNS, DHCP)",lambda r: r.get("funzioni", "")),
            ("os",       "  OS",                         lambda r: r.get("os", "")),
            ("cpu",      "  CPU",                        lambda r: r.get("cpu", "")),
            ("ram",      "  RAM (GB)",                   lambda r: r.get("ram", "")),
            ("dischi",   "  Dischi (es. 100 GB, 200 GB)",lambda r: r.get("dischi", "")),
        ],
        existing=existing or [],
    )


def collect_posta(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("POSTA")
    return {
        "locale":         ask("Posta locale (note)",        ex.get("locale", "")),
        "cloud_servizio": ask("Cloud - Servizio",           ex.get("cloud_servizio", "")),
        "cloud_cred":     ask("Cloud - Sito e Credenziali", ex.get("cloud_cred", "")),
    }


def collect_centralino(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("CENTRALINO")
    return {
        "tipo":        ask("Tipo centralino",  ex.get("tipo", "")),
        "ip":          ask("IP",               ex.get("ip", "")),
        "credenziali": ask_credenziali("",     ex.get("credenziali", "")),
        "linee":       ask("Linee",            ex.get("linee", "")),
        "telefoni":    ask("Telefoni",         ex.get("telefoni", "")),
    }


def collect_software_domarc(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("SOFTWARE DOMARC")
    return {
        "antivirus":    ask("Antivirus (numero postazioni e tipologia)", ex.get("antivirus", "")),
        "log_collector":ask("Log Collector (server e IP)",              ex.get("log_collector", "")),
        "datia":        ask("DATIA Monitor (server e IP)",              ex.get("datia", "")),
        "office365":    ask("Office 365 (caselle e tipologia)",         ex.get("office365", "")),
    }


def collect_servizi_cloud(existing: list = None) -> list:
    return collect_list_section(
        title="SERVIZI CLOUD", label="servizio cloud",
        fields=[
            ("nome",     "  Nome servizio",              lambda r: r.get("nome", "")),
            ("dettagli", "  Accesso, credenziali e note",lambda r: r.get("dettagli", "")),
        ],
        existing=existing or [],
    )


def collect_stampanti(existing: list = None) -> list:
    section_header("STAMPANTI")
    items = list(existing or [])
    for i, prev in enumerate(items):
        items[i] = ask(f"  Stampante {i+1} (nome/IP/modello)", prev)
    if items and not add_another("stampante"):
        return items
    while True:
        n = len(items) + 1
        items.append(ask(f"  Stampante {n} (nome/IP/modello)"))
        if not add_another("stampante"):
            break
    return items


def collect_backup(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("BACKUP")
    return {
        "locale":   ask("Backup locale (note)",                                   ex.get("locale", "")),
        "nas":      ask("Backup NAS (note)",                                      ex.get("nas", "")),
        "cloud":    ask("Backup Cloud (note)",                                    ex.get("cloud", "")),
        "software": ask("Software (es. VEEAM FREE, VEEAM ESSENTIAL, CLOUDBERRY)", ex.get("software", "")),
    }


def collect_gestionale(existing: list = None) -> list:
    return collect_list_section(
        title="GESTIONALE / SOFTWARE", label="gestionale/software",
        fields=[
            ("nome",       "  Nome software",         lambda r: r.get("nome", "")),
            ("assistenza", "  Riferimenti assistenza",lambda r: r.get("assistenza", "")),
        ],
        existing=existing or [],
    )


def collect_apparati(existing: dict = None) -> dict:
    ex = existing or {}
    section_header("APPARATI AGGIUNTIVI")
    return {
        "ups":      ask("UPS (marca, modello, data batterie, seriale, fornito da)", ex.get("ups", "")),
        "domotica": ask("Domotica (note)",  ex.get("domotica", "")),
        "altri":    ask("Altri apparati",   ex.get("altri", "")),
    }


def collect_licenze(existing: str = None) -> str:
    section_header("GESTIONE LICENZE PER CONTO CLIENTE")
    return collect_multiline("Inserisci note sulle licenze", default=existing or "")


# ─────────────────────────────────────────────
# RENDER FUNCTIONS
# ─────────────────────────────────────────────

def render_cliente(d: dict) -> str:
    return (
        f"# CLIENTE:\n\n"
        f"```\n"
        f"REFERENTE/I TECNICO: {d['referente']}\n"
        f"COD CLIENTE:         {d['cod_cliente']}\n"
        f"```"
    )


def render_accesso(d: dict) -> str:
    lines = ["# ACCESSO SERVIZI CLIENTE\n", "```"]
    for i, rdp in enumerate(d["rdp"], 1):
        label = f"RDP{i}:" if len(d["rdp"]) > 1 else "RDP:"
        lines.append(f"{label:<12}{rdp}")
    for i, tv in enumerate(d["teamviewer"], 1):
        label = f"TEAMVIEWER{i}:" if len(d["teamviewer"]) > 1 else "TEAMVIEWER:"
        lines.append(f"{label:<12}{tv}")
    for i, vpn in enumerate(d["vpn"], 1):
        label = f"VPN{i}:" if len(d["vpn"]) > 1 else "VPN:"
        lines.append(f"{label:<12}{vpn}")
    if d["bitwise"]:
        lines.append(f"{'BITWISE:':<12}{d['bitwise']}")
    lines.append("```")
    return "\n".join(lines)


def render_network(rows: list) -> str:
    lines = ["# NETWORK\n", "```"]
    lines.append(f"{'':12}{'ID':<6}{'SUBNET':<16}{'GTW':<16}{'DNS'}")
    for r in rows:
        lines.append(
            f"{'VLAN XXX:':<12}{r['id']:<6}{r['subnet']:<16}{r['gtw']:<16}{r['dns']}"
        )
        lines.append(f"    Note: {r['note']}")
    lines.append("```")
    return "\n".join(lines)


def render_switch(rows: list) -> str:
    lines = ["# SWITCH\n", "```"]
    lines.append(f"{'SW':<12}{'IP':<16}{'MODELLO':<14}{'CREDENZIALI':<20}{'SNMP'}")
    for r in rows:
        lines.append(
            f"    {r['nome']:<8}{r['ip']:<16}{r['modello']:<14}{r['credenziali']:<20}{r['snmp']}"
        )
        lines.append(f"    Note: {r['note']}")
    lines.append("```")
    return "\n".join(lines)


def render_firewall(d: dict) -> str:
    return (
        f"# FIREWALL\n\n"
        f"```\n"
        f"FWL Modello:     {d['modello']}\n"
        f"FWL SN:          {d['sn']}\n"
        f"FWL IP Interno:  {d['ip_interno']}\n"
        f"FWL IP Esterno:  {d['ip_esterno']}\n"
        f"FWL Credenziali: {d['credenziali']}\n"
        f"FWL SNMP:        {d['snmp']}\n"
        f"Note:            {d['note']}\n"
        f"```"
    )


def render_linee(rows: list) -> str:
    lines = ["# LINEE DATI\n", "```"]
    lines.append(f"{'':12}{'Provider':<12}{'IP/sub':<16}{'IP p2p':<16}{'router'}")
    for r in rows:
        lines.append(
            f"{r['nome']:<12}{r['provider']:<12}{r['ip_sub']:<16}{r['ip_p2p']:<16}{r['router']}"
        )
        lines.append(f"    Note: {r['note']}")
    lines.append("```")
    return "\n".join(lines)


def render_wifi(d: dict) -> str:
    lines = ["# WIFI\n", "```"]
    lines.append(f"WIFI CONTROLLER:             {d['controller']}")
    lines.append(f"WIFI CONTROLLER IP:          {d['controller_ip']}")
    lines.append(f"WIFI CONTROLLER credenziali: {d['controller_cred']}")
    lines.append("")
    for i, ap in enumerate(d["aps"], 1):
        lines.append(f"WIFI AP{i:02d}: {ap}")
    lines.append("")
    for i, s in enumerate(d["ssids"], 1):
        lines.append(f"WIFI SSID{i}: {s['ssid']:<20} WPA: {s['wpa']}")
    lines.append("")
    lines.append(f"Note: {d['note']}")
    lines.append("```")
    return "\n".join(lines)


def render_vpn(rows: list) -> str:
    lines = ["# VPN\n", "```"]
    for r in rows:
        lines.append(f"{r['nome']}:")
        lines.append(f"    {'Local Device':<20}{'Remote Device'}")
        lines.append(f"    {r['local_device']:<20}{r['remote_device']}")
        lines.append(f"    {'Local IP':<20}{'Remote IP'}")
        lines.append(f"    {r['local_ip']:<20}{r['remote_ip']}")
        lines.append(f"    {'Local Network':<20}{'Remote Network'}")
        lines.append(f"    {r['local_net']:<20}{r['remote_net']}")
        lines.append(f"    IKE par:   {r['ike']}")
        lines.append(f"    IPSEC Par: {r['ipsec']}")
        lines.append(f"    Note:      {r['note']}")
        lines.append("")
    lines.append("```")
    return "\n".join(lines)


def render_storage(rows: list) -> str:
    lines = ["# STORAGE\n", "```"]
    lines.append(
        f"{'NAS':<8}{'Modello':<16}{'IP':<16}{'Credenziali':<20}{'Spazio':<12}{'SNMP'}"
    )
    for r in rows:
        lines.append(
            f"{r['nome']:<8}{r['modello']:<16}{r['ip']:<16}{r['credenziali']:<20}{r['spazio']:<12}{r['snmp']}"
        )
        lines.append(f"    Note: {r['note']}")
    lines.append("```")
    return "\n".join(lines)


def render_ad(d: dict) -> str:
    # Compatibilità con vecchi JSON che avevano un unico campo "dominio"
    dominio_dns     = d.get("dominio_dns",     d.get("dominio", ""))
    dominio_netbios = d.get("dominio_netbios", "")
    return (
        f"# AD\n\n"
        f"```\n"
        f"DOMINIO DNS (FQDN):  {dominio_dns}\n"
        f"DOMINIO NETBIOS:     {dominio_netbios}\n"
        f"CREDENZIALI:         {d['credenziali']}\n"
        f"DNS:                 {d['dns']}\n"
        f"DHCP:                {d['dhcp']}\n"
        f"User DOMARC:         {d['user_domarc']}\n"
        f"DOMAIN CONTROLLER:   {d['dc']}\n"
        f"Note:                {d['note']}\n"
        f"```"
    )


def render_server_fisici(rows: list) -> str:
    lines = ["# SERVER FISICI\n", "```"]
    lines.append(
        f"{'SERVER':<12}{'MODELLO':<14}{'IP':<16}{'IP ILO':<16}{'CREDENZIALI':<20}{'SNMP'}"
    )
    for r in rows:
        lines.append(
            f"{r['nome']:<12}{r['modello']:<14}{r['ip']:<16}{r['ip_ilo']:<16}{r['credenziali']:<20}{r['snmp']}"
        )
        lines.append(f"    Note: {r['note']}")
    lines.append("```")
    return "\n".join(lines)


def render_virtualizzazione(d: dict) -> str:
    lines = ["# VIRTUALIZZAZIONE\n", "```"]
    tipo = d.get("tipo", "vmware")

    if tipo == "proxmox":
        lines.append(f"PIATTAFORMA:   Proxmox VE {d.get('versione', '')}")
        cluster = d.get("cluster", "")
        lines.append(f"CLUSTER:       {cluster if cluster else '(standalone)'}")
        lines.append("")
        lines.append(f"{'NODO':<16}{'IP':<16}{'CREDENZIALI'}")
        for nd in d.get("nodi", []):
            lines.append(f"{nd['nome']:<16}{nd['ip']:<16}{nd['credenziali']}")
        if d.get("note"):
            lines.append(f"\nNote: {d['note']}")
    else:
        # VMware (compatibilità anche con vecchi JSON senza campo "tipo")
        lines.append(f"PIATTAFORMA:   VMware")
        lines.append(f"{'':12}{'ver':<8}{'IP':<16}{'CREDENZIALI':<24}{'CREDENZIALI (5480)'}")
        lines.append(
            f"{'VCENTER':<12}{d.get('vcenter_ver',''):<8}{d.get('vcenter_ip',''):<16}"
            f"{d.get('vcenter_cred',''):<24}{d.get('vcenter_cred_5480','')}"
        )
        for i, esx in enumerate(d.get("esx", []), 1):
            lines.append(f"ESX{i:02d}       {esx}")

    lines.append("```")
    return "\n".join(lines)


def render_vm(rows: list) -> str:
    lines = ["# VM\n", "```"]
    lines.append(
        f"{'NOME':<12}{'IP':<16}{'FUNZIONI':<20}{'OS':<8}{'CPU':<5}{'RAM':<5}{'DISCHI'}"
    )
    for r in rows:
        lines.append(
            f"{r['nome']:<12}{r['ip']:<16}{r['funzioni']:<20}{r['os']:<8}{r['cpu']:<5}{r['ram']:<5}{r['dischi']}"
        )
    lines.append("```")
    return "\n".join(lines)


def render_posta(d: dict) -> str:
    return (
        f"# POSTA\n\n"
        f"```\n"
        f"locale:                   {d['locale']}\n"
        f"Cloud Servizio:           {d['cloud_servizio']}\n"
        f"Cloud Sito e Credenziali: {d['cloud_cred']}\n"
        f"```"
    )


def render_centralino(d: dict) -> str:
    return (
        f"# CENTRALINO\n\n"
        f"```\n"
        f"CENTRALINO TIPO:        {d['tipo']}\n"
        f"CENTRALINO IP:          {d['ip']}\n"
        f"CENTRALINO CREDENZIALI: {d['credenziali']}\n"
        f"CENTRALINO LINEE:       {d['linee']}\n"
        f"TELEFONI:               {d['telefoni']}\n"
        f"```"
    )


def render_software_domarc(d: dict) -> str:
    return (
        f"# SOFTWARE DOMARC\n\n"
        f"```\n"
        f"ANTIVIRUS:      {d['antivirus']}\n"
        f"LOG COLLECTOR:  {d['log_collector']}\n"
        f"DATIA MONITOR:  {d['datia']}\n"
        f"OFFICE 365:     {d['office365']}\n"
        f"```"
    )


def render_servizi_cloud(rows: list) -> str:
    lines = ["# SERVIZI CLOUD\n", "```"]
    for r in rows:
        lines.append(f"{r['nome']}: {r['dettagli']}")
    lines.append("```")
    return "\n".join(lines)


def render_stampanti(items: list) -> str:
    lines = ["# STAMPANTI\n", "```"]
    for i, s in enumerate(items, 1):
        lines.append(f"Stampante {i}: {s}")
    lines.append("```")
    return "\n".join(lines)


def render_backup(d: dict) -> str:
    locale_x = "X" if d["locale"] else " "
    nas_x    = "X" if d["nas"]    else " "
    cloud_x  = "X" if d["cloud"]  else " "
    return (
        f"# BACKUP\n\n"
        f"```\n"
        f"{'TIPO BACKUP':<16}{'LOCALE':<12}{'NAS':<12}{'CLOUD'}\n"
        f"{'':16}{locale_x:<12}{nas_x:<12}{cloud_x}\n"
        f"Locale: {d['locale']}\n"
        f"NAS:    {d['nas']}\n"
        f"Cloud:  {d['cloud']}\n"
        f"\nSOFTWARE: {d['software']}\n"
        f"```"
    )


def render_gestionale(rows: list) -> str:
    lines = ["# GESTIONALE/I o altri SOFTWARE\n", "```"]
    for r in rows:
        lines.append(f"SOFTWARE:              {r['nome']}")
        lines.append(f"RIFERIMENTI ASSISTENZA:{r['assistenza']}")
        lines.append("")
    lines.append("```")
    return "\n".join(lines)


def render_apparati(d: dict) -> str:
    return (
        f"# APPARATI AGGIUNTIVI\n\n"
        f"```\n"
        f"UPS:      {d['ups']}\n"
        f"DOMOTICA: {d['domotica']}\n"
        f"ALTRI:    {d['altri']}\n"
        f"```"
    )


def render_licenze(s: str) -> str:
    return f"# GESTIONE LICENZE PER CONTO CLIENTE\n\n```\n{s}\n```"


# ─────────────────────────────────────────────
# BUILD MARKDOWN
# ─────────────────────────────────────────────

MANDATORY_SECTIONS = [
    ("cliente",  render_cliente),
    ("accesso",  render_accesso),
    ("network",  render_network),
    ("switch",   render_switch),
    ("firewall", render_firewall),
    ("linee",    render_linee),
]

OPTIONAL_SECTIONS = [
    ("wifi",             render_wifi),
    ("vpn",              render_vpn),
    ("storage",          render_storage),
    ("ad",               render_ad),
    ("server_fisici",    render_server_fisici),
    ("virtualizzazione", render_virtualizzazione),
    ("vm",               render_vm),
    ("posta",            render_posta),
    ("centralino",       render_centralino),
    ("software_domarc",  render_software_domarc),
    ("servizi_cloud",    render_servizi_cloud),
    ("stampanti",        render_stampanti),
    ("backup",           render_backup),
    ("gestionale",       render_gestionale),
    ("apparati",         render_apparati),
    ("licenze",          render_licenze),
]

OPTIONAL_PROMPTS = {
    "wifi":             "Vuoi compilare la sezione WIFI?",
    "vpn":              "Vuoi compilare la sezione VPN?",
    "storage":          "Vuoi compilare la sezione STORAGE (NAS)?",
    "ad":               "Vuoi compilare la sezione AD (Active Directory)?",
    "server_fisici":    "Vuoi compilare la sezione SERVER FISICI?",
    "virtualizzazione": "Vuoi compilare la sezione VIRTUALIZZAZIONE?",
    "vm":               "Vuoi compilare la sezione VM?",
    "posta":            "Vuoi compilare la sezione POSTA?",
    "centralino":       "Vuoi compilare la sezione CENTRALINO?",
    "software_domarc":  "Vuoi compilare la sezione SOFTWARE DOMARC?",
    "servizi_cloud":    "Vuoi compilare la sezione SERVIZI CLOUD?",
    "stampanti":        "Vuoi compilare la sezione STAMPANTI?",
    "backup":           "Vuoi compilare la sezione BACKUP?",
    "gestionale":       "Vuoi compilare la sezione GESTIONALE/SOFTWARE?",
    "apparati":         "Vuoi compilare la sezione APPARATI AGGIUNTIVI?",
    "licenze":          "Vuoi compilare la sezione GESTIONE LICENZE?",
}

OPTIONAL_COLLECTORS = {
    "wifi":             collect_wifi,
    "vpn":              collect_vpn,
    "storage":          collect_storage,
    "ad":               collect_ad,
    "server_fisici":    collect_server_fisici,
    "virtualizzazione": collect_virtualizzazione,
    "vm":               collect_vm,
    "posta":            collect_posta,
    "centralino":       collect_centralino,
    "software_domarc":  collect_software_domarc,
    "servizi_cloud":    collect_servizi_cloud,
    "stampanti":        collect_stampanti,
    "backup":           collect_backup,
    "gestionale":       collect_gestionale,
    "apparati":         collect_apparati,
    "licenze":          collect_licenze,
}


def build_markdown(data: dict) -> str:
    parts = []
    nome = data["cliente"]["cliente"]
    parts.append(f"<!-- Cliente: {nome} -->\n")
    for key, render_fn in MANDATORY_SECTIONS:
        parts.append(render_fn(data[key]))
    for key, render_fn in OPTIONAL_SECTIONS:
        if key in data:
            parts.append(render_fn(data[key]))
    return "\n\n".join(parts)


# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────

def show_summary(data: dict, md_path: Path, json_path: Path) -> None:
    line = "═" * 44
    print(f"\n{line}")
    print("  RIEPILOGO")
    print(line)

    def check(key, label, count_fn=None):
        if key in data:
            suffix = f" ({count_fn(data[key])})" if count_fn else ""
            print(f"  [x] {label}{suffix}")
        else:
            print(f"  [ ] {label}")

    print(f"  [x] DATI CLIENTE         : {data['cliente']['cliente']} (cod: {data['cliente']['cod_cliente']})")
    print(f"  [x] ACCESSO SERVIZI")
    print(f"  [x] NETWORK              : {len(data['network'])} VLAN")
    print(f"  [x] SWITCH               : {len(data['switch'])} switch")
    print(f"  [x] FIREWALL")
    print(f"  [x] LINEE DATI           : {len(data['linee'])} linee")
    check("wifi",             "WIFI")
    check("vpn",              "VPN",           lambda x: f"{len(x)} tunnel")
    check("storage",          "STORAGE",       lambda x: f"{len(x)} NAS")
    check("ad",               "AD")
    check("server_fisici",    "SERVER FISICI", lambda x: f"{len(x)} server")
    check("virtualizzazione", "VIRTUALIZZAZIONE")
    check("vm",               "VM",            lambda x: f"{len(x)} VM")
    check("posta",            "POSTA")
    check("centralino",       "CENTRALINO")
    check("software_domarc",  "SOFTWARE DOMARC")
    check("servizi_cloud",    "SERVIZI CLOUD", lambda x: f"{len(x)} servizi")
    check("stampanti",        "STAMPANTI",     lambda x: f"{len(x)} stampanti")
    check("backup",           "BACKUP")
    check("gestionale",       "GESTIONALE",    lambda x: f"{len(x)} software")
    check("apparati",         "APPARATI AGGIUNTIVI")
    check("licenze",          "GESTIONE LICENZE")

    print(f"\n  MD  : {md_path}")
    print(f"  JSON: {json_path}")
    print(line)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main() -> None:
    print("\n" + "═" * 44)
    print("  CONFIG CLIENTE — Questionario")
    print("═" * 44)
    print("  Premi Invio per confermare il valore tra [].")
    print("  Ctrl+C per interrompere senza salvare.")
    print("═" * 44)

    try:
        # Carica file esistente o inizia da zero
        prev = pick_existing() or {}

        data: dict = {}

        # Sezioni obbligatorie
        data["cliente"] = collect_cliente(prev.get("cliente"))
        data["accesso"] = collect_accesso(prev.get("accesso"))
        data["network"] = collect_network(prev.get("network"))
        data["switch"]  = collect_switch(prev.get("switch"))
        data["firewall"]= collect_firewall(prev.get("firewall"))
        data["linee"]   = collect_linee(prev.get("linee"))

        # Selezione sezioni opzionali
        section_header("SEZIONI OPZIONALI")
        print("  Scegli quali sezioni compilare:\n")
        selected = {}
        for key in OPTIONAL_PROMPTS:
            # Default True se la sezione era già presente nel file caricato
            selected[key] = ask_yn(
                f"  {OPTIONAL_PROMPTS[key]}",
                default=key in prev,
            )

        # Raccolta sezioni opzionali selezionate
        for key in OPTIONAL_PROMPTS:
            if selected[key]:
                data[key] = OPTIONAL_COLLECTORS[key](prev.get(key))

        # Nome file output (basato sui dati correnti)
        cod  = sanitize_filename(data["cliente"]["cod_cliente"] or "NOCOD")
        nome = sanitize_filename(data["cliente"]["cliente"]     or "NOCLIENTE")
        base = f"{cod}_{nome}"
        client_dir = OUTPUT_DIR / base
        client_dir.mkdir(exist_ok=True)
        md_path   = client_dir / f"{base}.md"
        json_path = client_dir / f"{base}.json"

        # Scrittura file
        try:
            md_path.write_text(build_markdown(data), encoding="utf-8")
            save_json(data, json_path)
        except IOError as e:
            print(f"\nErrore nella scrittura del file: {e}", file=sys.stderr)
            sys.exit(1)

        show_summary(data, md_path, json_path)

    except KeyboardInterrupt:
        print("\n\nInterrotto dall'utente. Nessun file generato.")
        sys.exit(0)


if __name__ == "__main__":
    main()
