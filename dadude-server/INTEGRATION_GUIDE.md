# Device Backup Module - Integration Guide

Guida passo-passo per integrare il modulo backup nell'applicazione esistente **SENZA modificare codice esistente**.

---

## 📋 Step 1: Installazione Dipendenze

```bash
cd /Users/riccardo/Progetti/DATIA-inventtory/dadude

# Installa nuove dipendenze
pip install apscheduler>=3.10.4

# Opzionale: AI validation
pip install anthropic>=0.18.0
```

---

## 📋 Step 2: Migrazione Database

Crea le nuove tabelle:

```bash
python migrate_backup_tables.py --seed-templates
```

Output atteso:
```
✓ Created table: device_backups
✓ Created table: backup_schedules
✓ Created table: backup_jobs
✓ Created table: backup_templates
✓ Default templates seeded successfully
```

---

## 📋 Step 3: Configurazione Environment

Aggiungi al file `.env`:

```env
# === Device Backup Module ===
BACKUP_PATH=./backups
COMMANDS_LOG_PATH=./logs/commands

# AI Validation (opzionale)
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

---

## 📋 Step 4: Registrazione API Router

**File:** `app/main_dual.py` (file attivo per dual-port)

Aggiungi SOLO queste righe (non modificare altro):

```python
# === BACKUP MODULE INTEGRATION - START ===
# Aggiungi dopo gli import esistenti
from app.routers import device_backup

# Aggiungi dopo i router esistenti (cerca app.include_router)
app.include_router(
    device_backup.router,
    prefix="/api/v1",
    tags=["Device Backup"]
)

# Se vuoi backup automatici schedulati
from app.services.backup_scheduler import start_backup_scheduler, stop_backup_scheduler

# Aggiungi agli eventi startup/shutdown
@app.on_event("startup")
async def startup_backup_scheduler():
    start_backup_scheduler()

@app.on_event("shutdown")
async def shutdown_backup_scheduler():
    stop_backup_scheduler()
# === BACKUP MODULE INTEGRATION - END ===
```

**IMPORTANTE**: Aggiungi SOLO queste righe, non modificare il resto del file!

---

## 📋 Step 5: Verifica Funzionamento

### Test 1: API Disponibilità

Riavvia app:
```bash
# Con Docker
docker compose -f docker-compose-dual.yml restart

# Oppure locale
python -m app.run_dual
```

Verifica Swagger docs:
```
http://localhost:8000/docs
```

Dovresti vedere nuova sezione **"Device Backup"** con endpoints:
- POST `/api/v1/device-backup/device`
- POST `/api/v1/device-backup/customer`
- GET `/api/v1/device-backup/history/device/{id}`
- GET `/api/v1/device-backup/history/customer/{id}`
- POST `/api/v1/device-backup/schedule`
- etc.

### Test 2: Backup Manuale

```bash
curl -X POST "http://localhost:8000/api/v1/device-backup/device" \
  -H "Content-Type: application/json" \
  -d '{
    "device_ip": "192.168.1.10",
    "customer_id": "your-customer-id",
    "device_type": "hp_aruba",
    "backup_type": "config"
  }'
```

Response attesa:
```json
{
  "success": true,
  "backup_id": "abc12345",
  "message": "Backup completed successfully",
  "file_path": "./backups/hp_aruba/CUST001/switch-01/switch-01_20250115_153045.cfg"
}
```

### Test 3: Schedule Automatico

```bash
curl -X POST "http://localhost:8000/api/v1/device-backup/schedule" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_id": "your-customer-id",
    "enabled": true,
    "schedule_type": "daily",
    "schedule_time": "03:00",
    "retention_days": 30
  }'
```

---

## 🎨 Step 6: UI Integration (Frontend)

### Opzione A: Pulsante Backup nella Dashboard Device

**File:** `app/templates/devices.html` (o equivalente)

Aggiungi pulsante backup vicino a ogni device:

```html
<!-- Aggiungi button nella riga device -->
<button
  class="btn btn-sm btn-primary"
  onclick="backupDevice('{{ device.id }}')"
  title="Backup Configuration">
  <i class="fas fa-save"></i> Backup
</button>
```

**JavaScript:**
```javascript
async function backupDevice(deviceId) {
  try {
    // Show loading
    Swal.fire({
      title: 'Backup in corso...',
      allowOutsideClick: false,
      didOpen: () => Swal.showLoading()
    });

    // API call
    const response = await fetch('/api/v1/device-backup/device', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_assignment_id: deviceId,
        backup_type: 'config'
      })
    });

    const result = await response.json();

    if (result.success) {
      Swal.fire({
        icon: 'success',
        title: 'Backup Completato',
        html: `
          File: ${result.file_path}<br>
          Device: ${result.device_info?.system_name || 'Unknown'}<br>
          Dimensione: ${(result.device_info?.size_bytes / 1024).toFixed(2)} KB
        `
      });
    } else {
      Swal.fire({
        icon: 'error',
        title: 'Backup Fallito',
        text: result.error
      });
    }
  } catch (error) {
    Swal.fire({
      icon: 'error',
      title: 'Errore',
      text: error.message
    });
  }
}
```

### Opzione B: Modal Backup per Cliente

```html
<!-- Modal Backup Cliente -->
<div class="modal fade" id="backupModal">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5>Backup Dispositivi Cliente</h5>
      </div>
      <div class="modal-body">
        <p>Eseguire backup di tutti i dispositivi?</p>
        <div class="form-check">
          <input class="form-check-input" type="checkbox" id="includeConfig" checked>
          <label class="form-check-label">Backup Configurazione</label>
        </div>
        <div class="form-check">
          <input class="form-check-input" type="checkbox" id="includeBinary">
          <label class="form-check-label">Backup Binario (solo MikroTik)</label>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
        <button class="btn btn-primary" onclick="backupAllDevices()">Avvia Backup</button>
      </div>
    </div>
  </div>
</div>

<script>
async function backupAllDevices() {
  const customerId = getCurrentCustomerId(); // Implementa questa funzione

  const response = await fetch('/api/v1/device-backup/customer', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      customer_id: customerId,
      backup_type: 'config'
    })
  });

  const result = await response.json();

  if (result.success) {
    // Mostra progress del job
    trackBackupJob(result.job_id);
  }
}

async function trackBackupJob(jobId) {
  // Poll job status
  const interval = setInterval(async () => {
    const response = await fetch(`/api/v1/device-backup/job/${jobId}`);
    const job = await response.json();

    updateProgressBar(job.progress_percent);

    if (job.status === 'completed') {
      clearInterval(interval);
      showJobResult(job);
    }
  }, 2000);
}
</script>
```

### Opzione C: Pagina Backup Dedicata

Crea nuova pagina: `app/templates/device_backup.html`

```html
{% extends "base.html" %}

{% block content %}
<div class="container-fluid">
  <h2>Device Backup Management</h2>

  <!-- Backup History -->
  <div class="card mt-4">
    <div class="card-header">
      <h5>Backup History</h5>
    </div>
    <div class="card-body">
      <table class="table" id="backupHistoryTable">
        <thead>
          <tr>
            <th>Device</th>
            <th>Type</th>
            <th>Date</th>
            <th>Size</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="backupHistoryBody">
          <!-- Popolato via JS -->
        </tbody>
      </table>
    </div>
  </div>

  <!-- Schedule Configuration -->
  <div class="card mt-4">
    <div class="card-header">
      <h5>Backup Schedule</h5>
    </div>
    <div class="card-body">
      <form id="scheduleForm">
        <div class="row">
          <div class="col-md-3">
            <label>Schedule Type</label>
            <select class="form-control" id="scheduleType">
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
          </div>
          <div class="col-md-3">
            <label>Time (HH:MM)</label>
            <input type="time" class="form-control" id="scheduleTime" value="03:00">
          </div>
          <div class="col-md-3">
            <label>Retention (days)</label>
            <input type="number" class="form-control" id="retentionDays" value="30">
          </div>
          <div class="col-md-3">
            <label>&nbsp;</label>
            <button type="submit" class="btn btn-primary form-control">Save Schedule</button>
          </div>
        </div>
      </form>
    </div>
  </div>
</div>

<script>
// Load backup history
async function loadBackupHistory() {
  const customerId = getCurrentCustomerId();
  const response = await fetch(`/api/v1/device-backup/history/customer/${customerId}?days=30`);
  const data = await response.json();

  const tbody = document.getElementById('backupHistoryBody');
  tbody.innerHTML = data.backups.map(b => `
    <tr>
      <td>${b.device_hostname || b.device_ip}</td>
      <td>${b.device_type}</td>
      <td>${new Date(b.created_at).toLocaleString()}</td>
      <td>${(b.file_size / 1024).toFixed(2)} KB</td>
      <td>
        ${b.success
          ? '<span class="badge bg-success">Success</span>'
          : '<span class="badge bg-danger">Failed</span>'}
      </td>
      <td>
        <a href="/api/v1/device-backup/download/${b.id}" class="btn btn-sm btn-primary">
          <i class="fas fa-download"></i> Download
        </a>
      </td>
    </tr>
  `).join('');
}

// Save schedule
document.getElementById('scheduleForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const customerId = getCurrentCustomerId();

  await fetch('/api/v1/device-backup/schedule', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      customer_id: customerId,
      enabled: true,
      schedule_type: document.getElementById('scheduleType').value,
      schedule_time: document.getElementById('scheduleTime').value,
      retention_days: parseInt(document.getElementById('retentionDays').value),
      backup_types: ['config']
    })
  });

  Swal.fire('Success', 'Schedule saved', 'success');
});

// Load on page ready
document.addEventListener('DOMContentLoaded', loadBackupHistory);
</script>
{% endblock %}
```

---

## 📋 Step 7: Menu Navigation (Opzionale)

Aggiungi link nel menu principale:

**File:** `app/templates/base.html` o `sidebar.html`

```html
<!-- Nel menu sidebar -->
<li class="nav-item">
  <a class="nav-link" href="/device-backup">
    <i class="fas fa-save"></i>
    <span>Device Backups</span>
  </a>
</li>
```

Aggiungi route in `app/main_dual.py`:

```python
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/templates")

@app.get("/device-backup", include_in_schema=False)
async def device_backup_page(request: Request):
    return templates.TemplateResponse("device_backup.html", {"request": request})
```

---

## ✅ Checklist Finale

- [ ] Dipendenze installate
- [ ] Database migrato (tabelle backup create)
- [ ] `.env` configurato
- [ ] Router registrato in `main_dual.py`
- [ ] Scheduler avviato (se richiesto)
- [ ] API testate con curl/Postman
- [ ] UI integrata (pulsanti/modal/pagina)
- [ ] Menu navigation aggiunto (opzionale)
- [ ] Backup test eseguito con successo
- [ ] Schedule test configurato

---

## 🐛 Rollback (se necessario)

Se qualcosa non funziona, per fare rollback:

1. **Rimuovi router da main_dual.py** (commenta righe aggiunte)
2. **Stop scheduler** (commenta startup event)
3. **Drop tabelle** (opzionale):
   ```bash
   python migrate_backup_tables.py --force
   # Poi manualmente DROP TABLE device_backups, backup_schedules, etc.
   ```

L'applicazione esistente continuerà a funzionare normalmente.

---

## 📞 Support

Problemi? Controlla:
1. Logs: `./logs/`
2. Database: verifica tabelle create
3. API Swagger: `/docs`
4. Questo file: `DEVICE_BACKUP_MODULE.md`
