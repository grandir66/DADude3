# Miglioramento Supporto CLI Avanzata UniFi

## Informazione Utente

Su Ubiquiti UniFi è possibile accedere a una shell avanzata SSH con comandi CLI simili a Cisco:
- `cli` o `mca-cli` - entra in shell Cisco-like
- `enable` - modo privilegiato
- `configure` - modalità configurazione (simile a Cisco)
- Dopo `configure` c'è una configurazione simile a Cisco con comandi `show`

## Miglioramenti Implementati

### 1. Supporto Modalità Config

Aggiunto supporto per entrare in modalità `configure` dopo `enable`:

```python
# Prova 'configure' per entrare in modalità configurazione
channel.send("configure\n")
if 'config' in config_output.lower() or '(config)' in config_output.lower():
    in_config_mode = True
```

### 2. Migliorata Lettura Output

La funzione `cli_cmd` ora legge l'output in modo più robusto con iterazioni multiple:

```python
def cli_cmd(cmd: str, wait_time: float = 1.0) -> str:
    channel.send(f"{cmd}\n")
    time.sleep(wait_time)
    result = ""
    max_iterations = 10
    iteration = 0
    while iteration < max_iterations:
        if channel.recv_ready():
            chunk = channel.recv(4096).decode('utf-8', errors='ignore')
            result += chunk
            time.sleep(0.2)  # Piccola pausa per permettere più dati
        else:
            break
        iteration += 1
    return result
```

### 3. Parsing Migliorato Show Commands

#### Show Version
- Estrae `firmware_version`, `hardware_version`, `serial_number`, `model`
- Supporta vari formati di output

#### Show Interfaces Status
- Parsing completo per `show interfaces status` (formato Cisco-like)
- Estrae nome interfaccia, stato (up/down), speed
- Fallback a `show interfaces brief` se necessario

#### Show LLDP Neighbors Detail
- Parsing migliorato per estrarre informazioni complete sui neighbors
- Supporta vari formati di output UniFi

### 4. Gestione Corretta Modalità Config

Prima di eseguire comandi `show`, esce da config mode se necessario:

```python
# Esci da config mode se necessario prima di eseguire show commands
if in_config_mode:
    channel.send("exit\n")
    time.sleep(0.5)
    if channel.recv_ready():
        channel.recv(4096)
```

## Sequenza Comandi

1. **`cli`** - Entra in shell CLI avanzata
2. **`enable`** - Modo privilegiato
3. **`configure`** (opzionale) - Modalità configurazione
4. **`show version`** - Informazioni versione firmware/hardware
5. **`show interfaces status`** - Lista interfacce con stato
6. **`show lldp neighbors detail`** - Neighbors LLDP dettagliati
7. **`exit`** (se in config mode) - Esce da config mode
8. **`exit`** - Esce da enable mode
9. **`exit`** - Esce da CLI mode

## Comandi Supportati

### Show Commands (Cisco-like)
- `show version` - Versione firmware/hardware
- `show interfaces status` - Stato interfacce
- `show interfaces brief` - Interfacce (formato breve)
- `show lldp neighbors` - Neighbors LLDP (formato semplice)
- `show lldp neighbors detail` - Neighbors LLDP (formato dettagliato)
- `show running-config | include version` - Configurazione (se disponibile)

## Modifiche File

**File**: `dadude-agent/app/probes/ssh_probe.py`
- Funzione `_try_unifi_cli()` migliorata
- Aggiunto supporto per modalità config
- Migliorata lettura output con iterazioni multiple
- Parsing migliorato per tutti i comandi show

## Deploy

**Commit**: `bab22c0`  
**Data**: 2026-01-07 00:45  
**Container**: PCT 601 (dadude-agent-Domarc)  
**Versione**: v3.0.0

## Test

Per testare il miglioramento:

1. Eseguire una scansione su un dispositivo UniFi con shell avanzata
2. Verificare nei log che viene rilevata la modalità config:
   ```
   SSH probe: UniFi config mode entered on <target>
   ```
3. Verificare che i dati siano completi:
   - `interfaces` popolato da `show interfaces status`
   - `lldp_neighbors` popolato da `show lldp neighbors detail`
   - `firmware_version` e `model` estratti correttamente

## Note

- La modalità config viene rilevata automaticamente se presente
- I comandi `show` funzionano sia in enable mode che in config mode
- Alcuni UniFi potrebbero non supportare la modalità config, in quel caso funziona solo con enable
- La lettura dell'output è migliorata per gestire output lunghi o frammentati
