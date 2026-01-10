/**
 * DaDude - Unified Scanner Display Component
 * Visualizzazione grafica dei dati scansione per ogni tipo di dispositivo
 */

const UnifiedScannerDisplay = {
    // Icone per tipo dispositivo
    deviceIcons: {
        'router': 'bi-router',
        'switch': 'bi-diagram-3',
        'access_point': 'bi-wifi',
        'firewall': 'bi-shield-lock',
        'linux_server': 'bi-server',
        'windows_server': 'bi-pc-display',
        'proxmox': 'bi-boxes',
        'vmware': 'bi-cpu',
        'synology': 'bi-device-hdd',
        'qnap': 'bi-device-hdd-fill',
        'windows_workstation': 'bi-pc',
        'linux_workstation': 'bi-ubuntu',
        'printer': 'bi-printer',
        'ups': 'bi-battery-charging',
        'camera': 'bi-camera-video',
        'storage': 'bi-hdd-rack',
        'ilo_idrac': 'bi-motherboard',
        'unknown': 'bi-question-circle'
    },

    // Colori per tipo dispositivo
    deviceColors: {
        'router': '#6366f1',      // indigo
        'switch': '#0ea5e9',      // sky
        'access_point': '#22c55e', // green
        'firewall': '#ef4444',    // red
        'linux_server': '#f97316', // orange
        'windows_server': '#3b82f6', // blue
        'proxmox': '#8b5cf6',     // violet
        'vmware': '#06b6d4',      // cyan
        'synology': '#14b8a6',    // teal
        'qnap': '#10b981',        // emerald
        'windows_workstation': '#60a5fa', // blue-400
        'linux_workstation': '#fb923c', // orange-400
        'printer': '#a855f7',     // purple
        'ups': '#84cc16',         // lime
        'camera': '#f43f5e',      // rose
        'storage': '#64748b',     // slate
        'ilo_idrac': '#ec4899',   // pink
        'unknown': '#9ca3af'      // gray
    },

    /**
     * Genera HTML completo per visualizzare i risultati della scansione
     */
    render(result) {
        if (!result) {
            return '<div class="alert alert-warning">Nessun dato disponibile</div>';
        }

        // Se c'è un errore di connessione agent, mostralo in modo prominente
        if (result.agent_error) {
            return `
                <div class="unified-scan-result">
                    ${this.renderAgentError(result)}
                </div>
            `;
        }

        const deviceType = result.device_type || 'unknown';
        const color = this.deviceColors[deviceType] || this.deviceColors['unknown'];
        const icon = this.deviceIcons[deviceType] || this.deviceIcons['unknown'];

        return `
            <div class="unified-scan-result" style="--device-color: ${color}">
                ${this.renderHeader(result, icon, color)}
                ${this.renderCredentialTests(result)}
                ${this.renderSystemInfo(result)}
                ${this.renderHardwareSection(result)}
                ${this.renderNetworkSection(result)}
                ${this.renderVendorSpecificSection(result)}
                ${this.renderServicesSection(result)}
                ${this.renderStorageSection(result)}
                ${this.renderVMsSection(result)}
                ${this.renderErrorsSection(result)}
            </div>
        `;
    },

    /**
     * Mostra errore di connessione agent in modo prominente
     */
    renderAgentError(result) {
        const agentName = result.target || 'Agent';
        const errorMsg = result.agent_error || 'Agent non raggiungibile';
        
        return `
            <div class="alert alert-danger border-danger border-3 mb-4">
                <div class="d-flex align-items-start">
                    <div class="me-3">
                        <i class="bi bi-exclamation-triangle-fill fs-1 text-danger"></i>
                    </div>
                    <div class="flex-grow-1">
                        <h4 class="alert-heading mb-3">
                            <i class="bi bi-router me-2"></i>Agent "${agentName}" non raggiungibile
                        </h4>
                        <p class="mb-3">${errorMsg}</p>
                        <hr>
                        <p class="mb-2"><strong>Possibili cause:</strong></p>
                        <ul class="mb-3">
                            <li>Il servizio agent non è attivo</li>
                            <li>La connessione WebSocket è chiusa</li>
                            <li>L'endpoint HTTP non è raggiungibile</li>
                            <li>Problemi di rete tra server e agent</li>
                        </ul>
                        <p class="mb-0"><strong>Verifica:</strong></p>
                        <code class="d-block bg-dark text-light p-2 rounded mb-2">
                            ssh root@HOST "pct exec CONTAINER -- systemctl status dadude-agent"
                        </code>
                        <code class="d-block bg-dark text-light p-2 rounded">
                            ssh root@HOST "pct exec CONTAINER -- journalctl -u dadude-agent -n 50 --no-pager"
                        </code>
                    </div>
                </div>
            </div>
            <div class="alert alert-info">
                <i class="bi bi-info-circle me-2"></i>
                <strong>Nota:</strong> Questo errore indica un problema di connessione con l'agent, 
                non un problema con le credenziali del dispositivo. Una volta risolto il problema 
                di connessione, riprova la scansione.
            </div>
        `;
    },

    /**
     * Header con info dispositivo principale
     */
    renderHeader(result, icon, color) {
        const statusClass = result.status === 'success' ? 'success' : 
                           result.status === 'partial' ? 'warning' : 'danger';
        const statusText = result.status === 'success' ? 'Completato' : 
                          result.status === 'partial' ? 'Parziale' : 'Fallito';

        return `
            <div class="scan-header mb-4">
                <div class="d-flex align-items-center gap-3">
                    <div class="device-icon-large" style="background-color: ${color}">
                        <i class="bi ${icon}"></i>
                    </div>
                    <div class="flex-grow-1">
                        <h3 class="mb-1">${result.hostname || result.target || 'Dispositivo Sconosciuto'}</h3>
                        <div class="text-muted">
                            <span class="me-3"><i class="bi bi-hdd me-1"></i>${result.os_name || 'OS sconosciuto'} ${result.os_version || ''}</span>
                            <span class="me-3"><i class="bi bi-building me-1"></i>${result.manufacturer || 'N/A'}</span>
                            <span><i class="bi bi-tag me-1"></i>${result.model || 'N/A'}</span>
                        </div>
                    </div>
                    <div class="text-end">
                        <span class="badge bg-${statusClass} fs-6">${statusText}</span>
                        <div class="text-muted small mt-1">
                            <i class="bi bi-clock me-1"></i>${result.scan_duration_seconds?.toFixed(1) || '?'}s
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Sezione Test Credenziali
     */
    renderCredentialTests(result) {
        // Se c'è un errore agent, NON mostrare la tabella credenziali
        if (result.agent_error) return '';
        
        const tests = result.credential_tests || [];
        if (tests.length === 0) return '';

        // Raggruppa per protocollo per visualizzazione più chiara
        const byProtocol = {};
        tests.forEach(test => {
            const proto = test.protocol.toUpperCase();
            if (!byProtocol[proto]) {
                byProtocol[proto] = [];
            }
            byProtocol[proto].push(test);
        });

        return `
            <div class="card mb-4 border-primary">
                <div class="card-header bg-primary text-white">
                    <i class="bi bi-key me-2"></i>Test Credenziali
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-sm table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th style="width: 100px;">Protocollo</th>
                                    <th>Credenziale</th>
                                    <th style="width: 80px;">Risultato</th>
                                    ${tests.some(t => t.error) ? '<th>Errore</th>' : ''}
                                </tr>
                            </thead>
                            <tbody>
                                ${Object.keys(byProtocol).sort().map(proto => {
                                    return byProtocol[proto].map((test, idx) => {
                                        const isSuccess = test.status === 'success';
                                        const isFailed = test.status === 'failed';
                                        const isError = test.status === 'error';
                                        const isSkipped = test.status === 'skipped';
                                        
                                        // Determina nome credenziale da mostrare
                                        let credDisplay = test.credential_name || 'N/A';
                                        // Usa username/community se disponibili, altrimenti il nome credenziale
                                        if (proto === 'SSH' && test.username) {
                                            credDisplay = test.username;
                                        } else if (proto === 'SNMP' && test.community) {
                                            credDisplay = test.community;
                                        } else if ((proto === 'WMI' || proto === 'WINRM') && test.username) {
                                            credDisplay = test.domain ? `${test.domain}\\${test.username}` : test.username;
                                        }
                                        
                                        return `
                                            <tr class="${isSuccess ? 'table-success' : isFailed || isError ? 'table-danger' : isSkipped ? 'table-secondary' : ''}">
                                                <td><strong>${proto}</strong></td>
                                                <td><code>${credDisplay}</code></td>
                                                <td>
                                                    ${isSuccess ? '<span class="badge bg-success">OK</span>' : ''}
                                                    ${isFailed ? '<span class="badge bg-danger">KO</span>' : ''}
                                                    ${isError ? '<span class="badge bg-danger">ERR</span>' : ''}
                                                    ${isSkipped ? '<span class="badge bg-secondary">SKIP</span>' : ''}
                                                    ${!isSuccess && !isFailed && !isError && !isSkipped ? '<span class="badge bg-secondary">-</span>' : ''}
                                                </td>
                                                ${tests.some(t => t.error) ? `
                                                    <td><small class="text-muted">${test.error || '-'}</small></td>
                                                ` : ''}
                                            </tr>
                                        `;
                                    }).join('');
                                }).join('')}
                            </tbody>
                        </table>
                    </div>
                    ${result.credential_used ? `
                        <div class="mt-3 p-2 bg-light rounded">
                            <small class="text-muted">
                                <i class="bi bi-check-circle-fill text-success me-1"></i>
                                <strong>Credenziale funzionante:</strong> ${result.credential_used}
                            </small>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    },

    /**
     * Sezione Info Sistema
     */
    renderSystemInfo(result) {
        const items = [
            { label: 'Hostname', value: result.hostname, icon: 'bi-pc-display' },
            { label: 'IP', value: result.target, icon: 'bi-globe' },
            { label: 'MAC', value: result.primary_mac, icon: 'bi-ethernet' },
            { label: 'Serial', value: result.serial_number, icon: 'bi-upc' },
            { label: 'Uptime', value: result.uptime, icon: 'bi-clock-history' },
            { label: 'Firmware', value: result.firmware_version, icon: 'bi-gear' },
            { label: 'Protocollo', value: result.protocol_used, icon: 'bi-broadcast-pin' },
        ].filter(i => i.value);

        if (items.length === 0) return '';

        return `
            <div class="card mb-4">
                <div class="card-header">
                    <i class="bi bi-info-circle me-2"></i>Informazioni Sistema
                </div>
                <div class="card-body">
                    <div class="row g-3">
                        ${items.map(item => `
                            <div class="col-md-4 col-lg-3">
                                <div class="info-item">
                                    <i class="bi ${item.icon} text-primary"></i>
                                    <div>
                                        <div class="info-label">${item.label}</div>
                                        <div class="info-value">${item.value}</div>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Sezione Hardware (CPU, RAM)
     */
    renderHardwareSection(result) {
        const hasCpu = result.cpu_model || result.cpu_cores > 0;
        const hasRam = result.ram_total_gb > 0;

        if (!hasCpu && !hasRam) return '';

        return `
            <div class="card mb-4">
                <div class="card-header">
                    <i class="bi bi-cpu me-2"></i>Hardware
                </div>
                <div class="card-body">
                    <div class="row g-4">
                        ${hasCpu ? this.renderCpuCard(result) : ''}
                        ${hasRam ? this.renderRamCard(result) : ''}
                    </div>
                </div>
            </div>
        `;
    },

    renderCpuCard(result) {
        const usage = result.cpu_usage_percent || 0;
        const usageClass = usage < 50 ? 'success' : usage < 80 ? 'warning' : 'danger';

        return `
            <div class="col-md-6">
                <div class="hardware-card">
                    <div class="hw-icon"><i class="bi bi-cpu"></i></div>
                    <div class="hw-content">
                        <h6>CPU</h6>
                        <div class="hw-model">${result.cpu_model || 'N/A'}</div>
                        <div class="hw-specs">
                            <span><i class="bi bi-layers me-1"></i>${result.cpu_cores || 0} Core</span>
                            <span><i class="bi bi-grid-3x3 me-1"></i>${result.cpu_threads || 0} Thread</span>
                        </div>
                        ${usage > 0 ? `
                            <div class="progress mt-2" style="height: 8px;">
                                <div class="progress-bar bg-${usageClass}" style="width: ${usage}%"></div>
                            </div>
                            <small class="text-muted">${usage.toFixed(1)}% utilizzo</small>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    },

    renderRamCard(result) {
        const total = result.ram_total_gb || 0;
        const used = result.ram_used_gb || 0;
        const usage = result.ram_usage_percent || (total > 0 ? (used / total * 100) : 0);
        const usageClass = usage < 50 ? 'success' : usage < 80 ? 'warning' : 'danger';

        return `
            <div class="col-md-6">
                <div class="hardware-card">
                    <div class="hw-icon"><i class="bi bi-memory"></i></div>
                    <div class="hw-content">
                        <h6>Memoria RAM</h6>
                        <div class="hw-model">${this.formatBytes(total * 1024 * 1024 * 1024)}</div>
                        <div class="hw-specs">
                            <span><i class="bi bi-bar-chart me-1"></i>${this.formatBytes(used * 1024 * 1024 * 1024)} usati</span>
                        </div>
                        <div class="progress mt-2" style="height: 8px;">
                            <div class="progress-bar bg-${usageClass}" style="width: ${usage}%"></div>
                        </div>
                        <small class="text-muted">${usage.toFixed(1)}% utilizzo</small>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Sezione Network
     */
    renderNetworkSection(result) {
        const interfaces = result.interfaces || [];
        const neighbors = result.lldp_neighbors || [];

        if (interfaces.length === 0) return '';

        // Filtra solo interfacce attive o con IP
        // Supporta sia 'state'/'status' che 'admin_status'/'oper_status'
        const activeInterfaces = interfaces.filter(i => 
            i.state === 'up' || i.status === 'up' || 
            i.admin_status === 'up' || i.oper_status === 'up' ||
            i.running === true ||
            (i.ipv4_addresses && i.ipv4_addresses.length > 0)
        );

        return `
            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="bi bi-ethernet me-2"></i>Interfacce di Rete</span>
                    <span class="badge bg-primary">${activeInterfaces.length} attive / ${interfaces.length} totali</span>
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>Interfaccia</th>
                                    <th>Tipo</th>
                                    <th>MAC</th>
                                    <th>IP</th>
                                    <th>VLAN ID</th>
                                    <th>Velocità</th>
                                    <th>Duplex</th>
                                    <th>MTU</th>
                                    <th>Stato</th>
                                    <th>Description</th>
                                    <th>Traffico</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${interfaces.slice(0, 50).map(iface => {
                                    const isUp = iface.state === 'up' || iface.status === 'up' || 
                                                 iface.admin_status === 'up' || iface.oper_status === 'up' ||
                                                 iface.running === true;
                                    const statusText = iface.oper_status || iface.admin_status || iface.state || iface.status || 
                                                      (iface.running === true ? 'up' : 'down') || 'unknown';
                                    return `
                                    <tr class="${!isUp ? 'text-muted' : ''}">
                                        <td><strong>${iface.name || iface.if_index || '-'}</strong></td>
                                        <td><span class="badge bg-secondary">${iface.interface_type || iface.type || 'N/A'}</span></td>
                                        <td><code>${iface.mac_address || '-'}</code></td>
                                        <td>${Array.isArray(iface.ipv4_addresses) ? iface.ipv4_addresses.join(', ') : (iface.ipv4_addresses || iface.ip_address || '-')}</td>
                                        <td>${iface.vlan_id || '-'}</td>
                                        <td>${iface.speed_mbps > 0 ? iface.speed_mbps + ' Mbps' : (iface.speed || '-')}</td>
                                        <td>${iface.duplex || '-'}</td>
                                        <td>${iface.mtu || '-'}</td>
                                        <td>
                                            <span class="badge bg-${isUp ? 'success' : 'secondary'}">
                                                ${statusText}
                                            </span>
                                        </td>
                                        <td>${iface.description || '-'}</td>
                                        <td>
                                            <small>
                                                <i class="bi bi-arrow-down text-success"></i>${this.formatBytes(iface.rx_bytes || 0)}
                                                <i class="bi bi-arrow-up text-primary ms-2"></i>${this.formatBytes(iface.tx_bytes || 0)}
                                            </small>
                                        </td>
                                    </tr>`;
                                }).join('')}
                            </tbody>
                        </table>
                    </div>
                    ${interfaces.length > 50 ? `<div class="text-center text-muted py-2">...e altre ${interfaces.length - 50} interfacce</div>` : ''}
                </div>
            </div>
            ${neighbors.length > 0 ? this.renderNeighborsSection(neighbors) : ''}
        `;
    },

    renderNeighborsSection(neighbors) {
        return `
            <div class="card mb-4">
                <div class="card-header">
                    <i class="bi bi-diagram-2 me-2"></i>Vicini LLDP/CDP (${neighbors.length})
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>Porta Locale</th>
                                    <th>Dispositivo Remoto</th>
                                    <th>Porta Remota</th>
                                    <th>MAC Remoto</th>
                                    <th>IP Remoto</th>
                                    <th>Chassis ID</th>
                                    <th>Capabilities</th>
                                    <th>Descrizione</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${neighbors.map(n => `
                                    <tr>
                                        <td><code>${n.local_interface || n.local_port || '-'}</code></td>
                                        <td><strong>${n.remote_device_name || n.remote_device || n.remote_system_name || '-'}</strong></td>
                                        <td><code>${n.remote_port || n.remote_interface || n.remote_port_desc || '-'}</code></td>
                                        <td><code>${n.remote_mac || n.mac_address || '-'}</code></td>
                                        <td>${n.remote_ip || n.ip_address || '-'}</td>
                                        <td><code>${n.chassis_id || '-'}</code></td>
                                        <td>${n.capabilities || '-'}</td>
                                        <td>${n.remote_device_description || n.system_description || n.remote_system_desc || '-'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Sezione Dati Vendor-Specific
     */
    renderVendorSpecificSection(result) {
        const sections = [];
        
        // Routing Table
        if (result.routing_table && result.routing_table.length > 0) {
            sections.push(this.renderRoutingTable(result.routing_table));
        }
        
        // ARP Table
        if (result.arp_table && result.arp_table.length > 0) {
            sections.push(this.renderARPTable(result.arp_table));
        }
        
        // DHCP Leases (solo MikroTik)
        if (result.dhcp_leases && result.dhcp_leases.length > 0) {
            sections.push(this.renderDHCPLeases(result.dhcp_leases));
        }
        
        // CDP Neighbors (solo Cisco)
        if (result.cdp_neighbors && result.cdp_neighbors.length > 0) {
            sections.push(this.renderCDPNeighbors(result.cdp_neighbors));
        }
        
        // VLAN Information
        if (result.vlan_info && result.vlan_info.length > 0) {
            sections.push(this.renderVLANInfo(result.vlan_info));
        }
        
        return sections.join('');
    },

    renderRoutingTable(routes) {
        return `
            <div class="card mb-4">
                <div class="card-header">
                    <i class="bi bi-signpost-2 me-2"></i>Routing Table (${routes.length})
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>Destination</th>
                                    <th>Gateway</th>
                                    <th>Interface</th>
                                    <th>Distance</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${routes.map(route => `
                                    <tr>
                                        <td><code>${route.destination || route['dst-address'] || '-'}</code></td>
                                        <td>${route.gateway || route['gateway'] || route['nexthop'] || '-'}</td>
                                        <td><code>${route.interface || route['interface'] || route['out-interface'] || '-'}</code></td>
                                        <td>${route.distance || route['distance'] || '-'}</td>
                                        <td>
                                            <span class="badge bg-${route.status === 'active' || route['active'] === 'true' ? 'success' : 'secondary'}">
                                                ${route.status || (route['active'] === 'true' ? 'active' : 'inactive') || '-'}
                                            </span>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    },

    renderARPTable(arpEntries) {
        return `
            <div class="card mb-4">
                <div class="card-header">
                    <i class="bi bi-list-ul me-2"></i>ARP Table (${arpEntries.length})
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>IP Address</th>
                                    <th>MAC Address</th>
                                    <th>Interface</th>
                                    <th>Type</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${arpEntries.map(entry => `
                                    <tr>
                                        <td>${entry.address || entry.ip_address || entry['ip-address'] || '-'}</td>
                                        <td><code>${entry['mac-address'] || entry.mac_address || '-'}</code></td>
                                        <td><code>${entry.interface || '-'}</code></td>
                                        <td>
                                            <span class="badge bg-${entry.status === 'reachable' ? 'success' : entry.status === 'stale' || entry.status === 'delay' ? 'warning' : entry.status === 'failed' || entry.status === 'incomplete' ? 'danger' : 'secondary'}">
                                                ${entry.status || (entry.dynamic === 'true' ? 'Dynamic' : 'Static')}
                                            </span>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    },

    renderDHCPLeases(leases) {
        return `
            <div class="card mb-4">
                <div class="card-header">
                    <i class="bi bi-router me-2"></i>DHCP Leases (${leases.length})
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>IP Address</th>
                                    <th>MAC Address</th>
                                    <th>Hostname</th>
                                    <th>Expires</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${leases.map(lease => `
                                    <tr>
                                        <td>${lease.ip_address || lease['address'] || '-'}</td>
                                        <td><code>${lease.mac_address || lease['mac-address'] || '-'}</code></td>
                                        <td>${lease.hostname || lease['host-name'] || '-'}</td>
                                        <td>${lease.expires || lease['expires-after'] || lease['expires'] || '-'}</td>
                                        <td>
                                            <span class="badge bg-${lease.status === 'bound' || lease['status'] === 'bound' ? 'success' : 'secondary'}">
                                                ${lease.status || lease['status'] || '-'}
                                            </span>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    },

    renderCDPNeighbors(neighbors) {
        return `
            <div class="card mb-4">
                <div class="card-header">
                    <i class="bi bi-diagram-3 me-2"></i>CDP Neighbors (${neighbors.length})
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>Local Interface</th>
                                    <th>Remote Device</th>
                                    <th>Remote Port</th>
                                    <th>Platform</th>
                                    <th>Capabilities</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${neighbors.map(n => `
                                    <tr>
                                        <td><code>${n.local_interface || '-'}</code></td>
                                        <td><strong>${n.remote_device_name || '-'}</strong></td>
                                        <td><code>${n.remote_port || n.remote_interface || '-'}</code></td>
                                        <td>${n.platform || n.remote_platform || '-'}</td>
                                        <td>${n.capabilities || '-'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    },

    renderVLANInfo(vlans) {
        return `
            <div class="card mb-4">
                <div class="card-header">
                    <i class="bi bi-layers me-2"></i>VLAN Information (${vlans.length})
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>VLAN ID</th>
                                    <th>Name</th>
                                    <th>Status</th>
                                    <th>Ports</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${vlans.map(vlan => `
                                    <tr>
                                        <td><code>${vlan.vlan_id || vlan['vlan-id'] || '-'}</code></td>
                                        <td><strong>${vlan.name || vlan['vlan-name'] || '-'}</strong></td>
                                        <td>
                                            <span class="badge bg-${vlan.status === 'active' || vlan['status'] === 'active' ? 'success' : 'secondary'}">
                                                ${vlan.status || vlan['status'] || '-'}
                                            </span>
                                        </td>
                                        <td>${Array.isArray(vlan.ports) ? vlan.ports.join(', ') : (vlan.ports || '-')}</td>
                                        <td>${vlan.description || '-'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Sezione Servizi
     */
    renderServicesSection(result) {
        const services = result.services || [];
        if (services.length === 0) return '';

        const running = services.filter(s => s.status === 'running' || s.state === 'running').length;

        return `
            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="bi bi-gear-wide-connected me-2"></i>Servizi</span>
                    <span class="badge bg-success">${running} in esecuzione / ${services.length} totali</span>
                </div>
                <div class="card-body">
                    <div class="row g-2">
                        ${services.slice(0, 30).map(svc => `
                            <div class="col-md-4 col-lg-3">
                                <div class="service-item ${svc.status === 'running' || svc.state === 'running' ? 'running' : 'stopped'}">
                                    <i class="bi ${svc.status === 'running' || svc.state === 'running' ? 'bi-play-circle-fill text-success' : 'bi-stop-circle text-secondary'}"></i>
                                    <span class="service-name">${svc.name || svc.display_name || 'N/A'}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                    ${services.length > 30 ? `<div class="text-center text-muted mt-2">...e altri ${services.length - 30} servizi</div>` : ''}
                </div>
            </div>
        `;
    },

    /**
     * Sezione Storage
     */
    renderStorageSection(result) {
        const disks = result.disks || [];
        const volumes = result.volumes || [];
        
        if (disks.length === 0 && volumes.length === 0 && !result.disk_total_gb) return '';

        return `
            <div class="card mb-4">
                <div class="card-header">
                    <i class="bi bi-hdd me-2"></i>Storage
                </div>
                <div class="card-body">
                    ${result.disk_total_gb > 0 ? `
                        <div class="row mb-4">
                            <div class="col-md-6">
                                <div class="storage-summary">
                                    <div class="d-flex justify-content-between mb-2">
                                        <span>Spazio Totale</span>
                                        <strong>${result.disk_total_gb?.toFixed(1)} GB</strong>
                                    </div>
                                    <div class="progress" style="height: 20px;">
                                        <div class="progress-bar bg-primary" style="width: ${((result.disk_used_gb || 0) / result.disk_total_gb * 100).toFixed(1)}%">
                                            ${result.disk_used_gb?.toFixed(1)} GB usati
                                        </div>
                                    </div>
                                    <small class="text-muted">${result.disk_free_gb?.toFixed(1)} GB liberi</small>
                                </div>
                            </div>
                        </div>
                    ` : ''}
                    
                    ${volumes.length > 0 ? `
                        <h6 class="text-muted mb-3">Volumi</h6>
                        <div class="row g-3">
                            ${volumes.map(vol => `
                                <div class="col-md-4">
                                    <div class="volume-card">
                                        <div class="d-flex justify-content-between align-items-center mb-2">
                                            <strong><i class="bi bi-folder me-2"></i>${vol.mount_point || vol.drive_letter || 'Volume'}</strong>
                                            <span class="badge bg-secondary">${vol.filesystem || 'N/A'}</span>
                                        </div>
                                        <div class="progress mb-2" style="height: 8px;">
                                            <div class="progress-bar" style="width: ${vol.total_bytes > 0 ? (vol.used_bytes / vol.total_bytes * 100).toFixed(1) : 0}%"></div>
                                        </div>
                                        <small class="text-muted">
                                            ${this.formatBytes(vol.used_bytes || 0)} / ${this.formatBytes(vol.total_bytes || 0)}
                                        </small>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    },

    /**
     * Sezione VMs (Proxmox/VMware)
     */
    renderVMsSection(result) {
        const vms = result.vms || [];
        if (vms.length === 0) return '';

        const running = vms.filter(v => v.status === 'running' || v.power_state === 'poweredOn').length;

        return `
            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="bi bi-boxes me-2"></i>Macchine Virtuali</span>
                    <span class="badge bg-success">${running} attive / ${vms.length} totali</span>
                </div>
                <div class="card-body p-0">
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>Nome</th>
                                    <th>ID</th>
                                    <th>Stato</th>
                                    <th>CPU</th>
                                    <th>RAM</th>
                                    <th>OS</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${vms.map(vm => `
                                    <tr>
                                        <td><strong>${vm.name || 'N/A'}</strong></td>
                                        <td><code>${vm.id || vm.vmid || '-'}</code></td>
                                        <td>
                                            <span class="badge bg-${vm.status === 'running' || vm.power_state === 'poweredOn' ? 'success' : 'secondary'}">
                                                ${vm.status || vm.power_state || 'unknown'}
                                            </span>
                                        </td>
                                        <td>${vm.cpus || vm.num_cpus || '-'}</td>
                                        <td>${vm.memory_mb ? (vm.memory_mb / 1024).toFixed(1) + ' GB' : (vm.memory_gb || '-')}</td>
                                        <td>${vm.os_type || vm.guest_os || '-'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Sezione Errori/Warning
     */
    renderErrorsSection(result) {
        const errors = result.errors || [];
        const warnings = result.warnings || [];

        if (errors.length === 0 && warnings.length === 0) return '';

        return `
            <div class="row g-4">
                ${errors.length > 0 ? `
                    <div class="col-md-6">
                        <div class="alert alert-danger mb-0">
                            <h6><i class="bi bi-exclamation-triangle me-2"></i>Errori (${errors.length})</h6>
                            <ul class="mb-0">
                                ${errors.map(e => `<li>${e}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                ` : ''}
                ${warnings.length > 0 ? `
                    <div class="col-md-6">
                        <div class="alert alert-warning mb-0">
                            <h6><i class="bi bi-exclamation-circle me-2"></i>Avvisi (${warnings.length})</h6>
                            <ul class="mb-0">
                                ${warnings.map(w => `<li>${w}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    },

    /**
     * Utility: formatta bytes in formato leggibile
     */
    formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
};

// Esporta per uso globale
window.UnifiedScannerDisplay = UnifiedScannerDisplay;
