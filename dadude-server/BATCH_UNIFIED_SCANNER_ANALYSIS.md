# Analisi: Batch Unified Scanner - Scansione Multi-Device

**Data**: 2026-01-11  
**Versione**: 3.2.0  
**Stato**: Da implementare

---

## 📋 Obiettivo

Implementare la funzionalità di scansione batch con Unified Scanner per permettere la scansione di più dispositivi selezionati contemporaneamente, evitando i modali individuali di fine scansione e mostrando invece un unico modal di progresso con stato complessivo.

---

## 🎯 Requisiti Funzionali

### 1. Selezione Multipla Device
- ✅ Selezione multipla nella tabella inventory (checkbox già presente)
- ✅ Bottone "Scansione Unificata Batch" nella toolbar
- ✅ Validazione: almeno 1 device selezionato

### 2. Modalità di Scansione
- **Sequenziale**: Scansione un device alla volta (default per evitare sovraccarico agent)
- **Parallela**: Scansione multipla con semaforo (max 3-5 concurrent)
- **Auto-save**: Opzione per salvare automaticamente i risultati nel database

### 3. UI/UX
- **Modal di progresso globale** invece di modali individuali:
  - Progress bar complessiva (0-100%)
  - Lista device con stato individuale (✅ Success, ⏳ In corso, ❌ Failed)
  - Contatori: `X/Y completati`, `Z falliti`
  - Dettagli per device: protocollo usato, credenziale usata, errori
- **Nessun modal di risultato individuale** - solo summary finale
- **Possibilità di chiudere il modal** durante la scansione (continua in background)

### 4. Risultati
- **Summary finale** con:
  - Totale device scansionati
  - Successi/Fallimenti
  - Lista errori (se presenti)
  - Tempo totale impiegato
- **Auto-save opzionale** dei risultati nel database

---

## 🏗️ Architettura

### Backend

#### 1. Nuovo Endpoint: `POST /api/v1/unified-scanner/batch-scan`

```python
class BatchUnifiedScanRequest(BaseModel):
    """Richiesta scansione batch unificata"""
    device_ids: List[str] = Field(..., description="Lista ID dispositivi da scansionare")
    customer_id: str = Field(..., description="ID cliente")
    agent_id: Optional[str] = Field(None, description="ID agent da usare")
    protocols: List[str] = Field(default=["auto"], description="Protocolli da usare")
    timeout: int = Field(120, ge=10, le=600)
    include_software: bool = Field(True)
    include_services: bool = Field(True)
    include_users: bool = Field(False)
    auto_save: bool = Field(True, description="Salva automaticamente i risultati")
    mode: str = Field("sequential", description="sequential o parallel")
    max_concurrent: int = Field(3, ge=1, le=10, description="Max scansioni parallele (solo se mode=parallel)")
```

#### 2. Struttura Risposta

```python
class BatchScanStatus(BaseModel):
    """Stato scansione batch"""
    batch_id: str  # ID univoco batch
    total: int  # Totale device
    completed: int  # Completati
    failed: int  # Falliti
    in_progress: int  # In corso
    status: str  # "running", "completed", "failed"
    results: List[Dict[str, Any]]  # Risultati per device
    errors: List[str]  # Errori globali
    start_time: datetime
    estimated_completion: Optional[datetime]
```

#### 3. Endpoint Status: `GET /api/v1/unified-scanner/batch-status/{batch_id}`

```python
@router.get("/batch-status/{batch_id}")
async def get_batch_scan_status(batch_id: str):
    """Ottiene lo stato corrente di una scansione batch"""
    # Legge da file condiviso o cache
    # Restituisce BatchScanStatus
```

### Frontend

#### 1. Selezione Device
- Usa checkbox esistenti nella tabella inventory
- Bottone "Scansione Unificata Batch" nella toolbar (solo se device selezionati)

#### 2. Modal Configurazione
- Protocolli (auto, ssh, snmp, winrm)
- Opzioni (include_software, include_services, include_users)
- Auto-save (default: true)
- Modalità (Sequenziale/Parallela)

#### 3. Modal Progresso
```html
<div class="modal" id="batchScanProgressModal">
  <div class="modal-header">
    <h5>Scansione Batch in corso</h5>
  </div>
  <div class="modal-body">
    <!-- Progress bar globale -->
    <div class="progress mb-3">
      <div id="batchProgressBar">0%</div>
    </div>
    
    <!-- Contatori -->
    <div class="row mb-3">
      <div class="col">
        <strong>Totale:</strong> <span id="batchTotal">0</span>
      </div>
      <div class="col">
        <strong>Completati:</strong> <span id="batchCompleted">0</span>
      </div>
      <div class="col">
        <strong>Falliti:</strong> <span id="batchFailed">0</span>
      </div>
    </div>
    
    <!-- Lista device con stato -->
    <div id="batchDeviceList">
      <!-- Ogni device mostra:
           - Nome/IP
           - Stato: ⏳ In corso | ✅ Success | ❌ Failed
           - Protocollo/Credenziale (se disponibile)
           - Errore (se failed)
      -->
    </div>
  </div>
  <div class="modal-footer">
    <button onclick="closeBatchScanModal()">Chiudi (continua in background)</button>
  </div>
</div>
```

#### 4. Polling Status
- Polling ogni 1 secondo su `/api/v1/unified-scanner/batch-status/{batch_id}`
- Aggiorna UI con stato corrente
- Quando `status === "completed"`, mostra summary finale

---

## 🔧 Implementazione

### Backend: `dadude-server/app/routers/unified_scanner.py`

#### 1. Aggiungi modello richiesta batch

```python
class BatchUnifiedScanRequestModel(BaseModel):
    device_ids: List[str] = Field(..., min_items=1)
    customer_id: str
    agent_id: Optional[str] = None
    protocols: List[str] = Field(default=["auto"])
    timeout: int = Field(120, ge=10, le=600)
    include_software: bool = Field(True)
    include_services: bool = Field(True)
    include_users: bool = Field(False)
    auto_save: bool = Field(True)
    mode: str = Field("sequential", pattern="^(sequential|parallel)$")
    max_concurrent: int = Field(3, ge=1, le=10)
```

#### 2. Endpoint batch scan

```python
@router.post("/batch-scan")
async def batch_unified_scan(request: BatchUnifiedScanRequestModel):
    """
    Esegue scansione unificata su più dispositivi.
    
    Modalità:
    - sequential: Scansione sequenziale (una alla volta)
    - parallel: Scansione parallela con semaforo (max_concurrent)
    
    Ritorna immediatamente con batch_id per polling status.
    """
    import uuid
    batch_id = str(uuid.uuid4())
    
    # Recupera device dal database
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    
    settings = get_settings()
    engine = init_db(settings.database_url)
    session = get_session(engine)
    
    try:
        devices = session.query(InventoryDevice).filter(
            InventoryDevice.id.in_(request.device_ids),
            InventoryDevice.customer_id == request.customer_id
        ).all()
        
        if not devices:
            raise HTTPException(status_code=404, detail="Nessun dispositivo trovato")
        
        # Inizializza stato batch
        scanner = get_unified_scanner_service()
        scanner.set_batch_status(batch_id, {
            "batch_id": batch_id,
            "total": len(devices),
            "completed": 0,
            "failed": 0,
            "in_progress": 0,
            "status": "running",
            "results": [],
            "errors": [],
            "start_time": datetime.utcnow().isoformat(),
            "device_statuses": {d.id: "pending" for d in devices}
        })
        
        # Avvia scansione in background
        asyncio.create_task(
            _execute_batch_scan_background(
                batch_id=batch_id,
                devices=devices,
                request=request,
                scanner=scanner,
                agent_service=get_agent_service(),
                customer_service=get_customer_service()
            )
        )
        
        return {
            "success": True,
            "batch_id": batch_id,
            "status": "running",
            "total": len(devices),
            "message": f"Scansione batch avviata per {len(devices)} dispositivi"
        }
        
    finally:
        session.close()
```

#### 3. Funzione background batch scan

```python
async def _execute_batch_scan_background(
    batch_id: str,
    devices: List[InventoryDevice],
    request: BatchUnifiedScanRequestModel,
    scanner,
    agent_service,
    customer_service
):
    """Esegue scansione batch in background"""
    import asyncio
    
    results = []
    errors = []
    
    if request.mode == "sequential":
        # Scansione sequenziale
        for device in devices:
            try:
                # Aggiorna stato: in corso
                scanner.update_batch_device_status(batch_id, device.id, "running")
                
                # Esegui scansione
                scan_request = UnifiedScanRequest(
                    device_id=device.id,
                    target_address=device.primary_ip or device.mac_address,
                    customer_id=request.customer_id,
                    agent_id=request.agent_id,
                    protocols=request.protocols,
                    credentials_list=await _get_all_credentials_for_scan(...),
                    timeout=request.timeout,
                    include_software=request.include_software,
                    include_services=request.include_services,
                    include_users=request.include_users,
                )
                
                result = await scanner.scan_device(
                    scan_request,
                    agent_service=agent_service,
                    scan_id=f"{batch_id}-{device.id}"
                )
                
                # Auto-save se richiesto
                if request.auto_save:
                    await _save_unified_scan_to_inventory(device.id, result, session)
                
                # Aggiorna stato: completato
                scanner.update_batch_device_status(
                    batch_id, 
                    device.id, 
                    "completed",
                    result=result.to_dict()
                )
                
                results.append({
                    "device_id": device.id,
                    "address": device.primary_ip,
                    "success": True,
                    "result": result.to_dict()
                })
                
            except Exception as e:
                logger.error(f"Error scanning {device.id}: {e}")
                scanner.update_batch_device_status(
                    batch_id,
                    device.id,
                    "failed",
                    error=str(e)
                )
                errors.append(f"{device.primary_ip}: {str(e)}")
                results.append({
                    "device_id": device.id,
                    "address": device.primary_ip,
                    "success": False,
                    "error": str(e)
                })
    
    else:
        # Scansione parallela con semaforo
        semaphore = asyncio.Semaphore(request.max_concurrent)
        
        async def scan_one_device(device):
            async with semaphore:
                # Stesso codice della scansione sequenziale
                ...
        
        tasks = [scan_one_device(d) for d in devices]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    # Aggiorna stato finale
    scanner.update_batch_status(batch_id, {
        "status": "completed",
        "completed": len([r for r in results if r.get("success")]),
        "failed": len([r for r in results if not r.get("success")]),
        "results": results,
        "errors": errors
    })
```

#### 4. Gestione stato batch (in `unified_scanner_service.py`)

```python
# Aggiungi a UnifiedScannerService
BATCH_STATUS_FILE = "/tmp/dadude_batch_status.json"

def set_batch_status(self, batch_id: str, status: Dict[str, Any]):
    """Salva stato batch su file condiviso"""
    all_batches = self._load_batch_status()
    all_batches[batch_id] = status
    self._save_batch_status(all_batches)

def get_batch_status(self, batch_id: str) -> Optional[Dict[str, Any]]:
    """Legge stato batch da file condiviso"""
    all_batches = self._load_batch_status()
    return all_batches.get(batch_id)

def update_batch_device_status(self, batch_id: str, device_id: str, status: str, **kwargs):
    """Aggiorna stato di un device nel batch"""
    batch_status = self.get_batch_status(batch_id)
    if batch_status:
        batch_status["device_statuses"][device_id] = status
        if "result" in kwargs:
            batch_status.setdefault("results", []).append({
                "device_id": device_id,
                "status": status,
                **kwargs
            })
        self.set_batch_status(batch_id, batch_status)
```

### Frontend: `dadude-server/app/templates/customer_detail.html`

#### 1. Bottone batch scan nella toolbar

```javascript
// Aggiungi dopo altri bottoni nella toolbar
function showBatchUnifiedScanModal() {
    const selectedDevices = getSelectedDevices(); // Funzione esistente
    
    if (selectedDevices.length === 0) {
        showToast('Seleziona almeno un dispositivo', 'warning');
        return;
    }
    
    // Mostra modal configurazione (simile a unified scan singolo)
    const modalContent = `
        <div class="mb-3">
            <h6>Scansione Batch: ${selectedDevices.length} dispositivi</h6>
            <p class="text-muted">Configura le opzioni di scansione per tutti i dispositivi selezionati.</p>
        </div>
        
        <!-- Protocolli, opzioni, auto-save, mode -->
        ...
        
        <button class="btn btn-primary" onclick="startBatchUnifiedScan(${JSON.stringify(selectedDevices)})">
            Avvia Scansione Batch
        </button>
    `;
    
    showModal('Configurazione Scansione Batch', modalContent, 'lg');
}

async function startBatchUnifiedScan(deviceIds) {
    // Raccogli configurazione
    const protocols = [...]; // Da checkbox
    const autoSave = document.getElementById('batchAutoSave').checked;
    const mode = document.getElementById('batchMode').value; // sequential/parallel
    
    try {
        const response = await fetch('/api/v1/unified-scanner/batch-scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                device_ids: deviceIds,
                customer_id: customerId,
                protocols: protocols,
                auto_save: autoSave,
                mode: mode,
                max_concurrent: mode === 'parallel' ? 3 : 1,
                timeout: 120,
                include_software: true,
                include_services: true,
                include_users: false
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Mostra modal progresso
            showBatchScanProgressModal(result.batch_id, result.total);
            
            // Avvia polling
            await pollBatchScanStatus(result.batch_id);
        }
    } catch (error) {
        showToast('Errore: ' + error.message, 'danger');
    }
}

function showBatchScanProgressModal(batchId, total) {
    const modalContent = `
        <div class="text-center mb-3">
            <h5>Scansione Batch in corso</h5>
            <p class="text-muted">ID: <code>${batchId}</code></p>
        </div>
        
        <div class="progress mb-3" style="height: 30px;">
            <div id="batchProgressBar" class="progress-bar progress-bar-striped progress-bar-animated" 
                 style="width: 0%">0%</div>
        </div>
        
        <div class="row mb-3 text-center">
            <div class="col">
                <strong>Totale:</strong> <span id="batchTotal">${total}</span>
            </div>
            <div class="col">
                <strong>Completati:</strong> <span id="batchCompleted" class="text-success">0</span>
            </div>
            <div class="col">
                <strong>Falliti:</strong> <span id="batchFailed" class="text-danger">0</span>
            </div>
        </div>
        
        <div id="batchDeviceList" class="list-group" style="max-height: 400px; overflow-y: auto;">
            <!-- Popolato via polling -->
        </div>
    `;
    
    showModal('Scansione Batch', modalContent, 'lg');
}

async function pollBatchScanStatus(batchId) {
    const maxWaitMs = 600000; // 10 minuti
    const pollIntervalMs = 1000; // 1 secondo
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitMs) {
        try {
            const response = await fetch(`/api/v1/unified-scanner/batch-status/${batchId}`);
            const data = await response.json();
            
            if (data.success && data.status) {
                const status = data.status;
                
                // Aggiorna progress bar
                const progress = Math.round((status.completed / status.total) * 100);
                document.getElementById('batchProgressBar').style.width = `${progress}%`;
                document.getElementById('batchProgressBar').textContent = `${progress}%`;
                
                // Aggiorna contatori
                document.getElementById('batchCompleted').textContent = status.completed;
                document.getElementById('batchFailed').textContent = status.failed;
                
                // Aggiorna lista device
                updateBatchDeviceList(status.device_statuses, status.results);
                
                // Se completato, mostra summary
                if (status.status === 'completed') {
                    showBatchScanSummary(status);
                    return;
                }
            }
        } catch (error) {
            console.error('Error polling batch status:', error);
        }
        
        await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
    }
}

function updateBatchDeviceList(deviceStatuses, results) {
    const listDiv = document.getElementById('batchDeviceList');
    // Aggiorna lista con stato corrente di ogni device
    // Usa deviceStatuses per stato (pending/running/completed/failed)
    // Usa results per dettagli (protocollo, credenziale, errori)
}

function showBatchScanSummary(status) {
    // Mostra summary finale con risultati completi
    // Chiudi modal progresso e mostra modal summary
}
```

---

## 📊 File di Stato Condiviso

Simile a `/tmp/dadude_scan_status.json`, creare `/tmp/dadude_batch_status.json`:

```json
{
  "batch-123": {
    "batch_id": "batch-123",
    "total": 5,
    "completed": 3,
    "failed": 1,
    "in_progress": 1,
    "status": "running",
    "results": [...],
    "errors": [...],
    "device_statuses": {
      "device-1": "completed",
      "device-2": "running",
      "device-3": "failed",
      ...
    }
  }
}
```

---

## ✅ Checklist Implementazione

### Backend
- [ ] Aggiungere `BatchUnifiedScanRequestModel`
- [ ] Implementare `POST /api/v1/unified-scanner/batch-scan`
- [ ] Implementare `GET /api/v1/unified-scanner/batch-status/{batch_id}`
- [ ] Aggiungere metodi `set_batch_status`, `get_batch_status`, `update_batch_device_status` in `UnifiedScannerService`
- [ ] Implementare `_execute_batch_scan_background` con modalità sequenziale
- [ ] Implementare modalità parallela con semaforo
- [ ] Gestione errori e logging

### Frontend
- [ ] Aggiungere bottone "Scansione Unificata Batch" nella toolbar
- [ ] Implementare `showBatchUnifiedScanModal()` - modal configurazione
- [ ] Implementare `startBatchUnifiedScan()` - avvio scansione
- [ ] Implementare `showBatchScanProgressModal()` - modal progresso
- [ ] Implementare `pollBatchScanStatus()` - polling stato
- [ ] Implementare `updateBatchDeviceList()` - aggiornamento lista device
- [ ] Implementare `showBatchScanSummary()` - summary finale
- [ ] Gestione chiusura modal durante scansione (continua in background)

### Testing
- [ ] Test scansione sequenziale con 3-5 device
- [ ] Test scansione parallela con semaforo
- [ ] Test gestione errori (device non raggiungibile, agent offline)
- [ ] Test auto-save risultati
- [ ] Test UI con molti device (10+)
- [ ] Test chiusura modal durante scansione

---

## 🚀 Note Implementative

1. **Performance**: 
   - Modalità sequenziale per evitare sovraccarico agent
   - Modalità parallela con semaforo (max 3-5) per velocizzare

2. **Error Handling**:
   - Un device fallito non blocca gli altri
   - Errori dettagliati per ogni device nel summary

3. **UI/UX**:
   - Progress bar globale + lista device individuale
   - Possibilità di chiudere modal (continua in background)
   - Summary finale con possibilità di vedere dettagli per device

4. **Stato Condiviso**:
   - Usa file JSON condiviso tra processi (come scan singolo)
   - Path: `/tmp/dadude_batch_status.json`

5. **Compatibilità**:
   - Riutilizza logica esistente di `unified_scan` singolo
   - Riutilizza `_save_unified_scan_to_inventory` per auto-save

---

## 📝 Esempio Flusso

1. Utente seleziona 5 device nella tabella inventory
2. Clicca "Scansione Unificata Batch"
3. Si apre modal configurazione (protocolli, opzioni, auto-save, mode)
4. Utente clicca "Avvia Scansione Batch"
5. Backend crea `batch_id` e ritorna immediatamente
6. Frontend mostra modal progresso con:
   - Progress bar: 0%
   - Lista 5 device tutti "⏳ In attesa"
7. Backend inizia scansione sequenziale:
   - Device 1: ⏳ In corso → ✅ Success (SSH, credenziale X)
   - Device 2: ⏳ In corso → ❌ Failed (Agent non raggiungibile)
   - Device 3: ⏳ In corso → ✅ Success (SNMP, credenziale Y)
   - ...
8. Frontend aggiorna ogni secondo:
   - Progress bar: 20%, 40%, 60%...
   - Contatori: Completati: 2, Falliti: 1
   - Lista device con stati aggiornati
9. Al completamento (100%):
   - Modal progresso si chiude
   - Si apre modal summary con:
     - ✅ 4 successi, ❌ 1 fallito
     - Lista dettagliata risultati
     - Possibilità di vedere dettagli per device

---

**Fine Analisi**
