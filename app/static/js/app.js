// Net Sentinel by Software Vantage - Core Dashboard Application
(function () {
  'use strict';

  // Application State
  const state = {
    devices: [],
    summary: {},
    settings: {},
    activeFilter: 'all',
    searchQuery: '',
    currentDevice: null,
    blockTargetDevice: null,
    auth: {
      adminExists: false,
      authenticated: false,
      username: null,
      csrfToken: null
    }
  };

  // DOM Elements
  const el = {
    // Navigation
    navItems: document.querySelectorAll('.nav-item'),
    tabPanes: document.querySelectorAll('.tab-pane'),
    pageTitle: document.getElementById('pageTitle'),
    mobileMenuBtn: document.getElementById('mobileMenuBtn'),
    sidebar: document.querySelector('.sidebar'),

    // Top actions
    btnRefresh: document.getElementById('btnRefresh'),
    btnScanTrigger: document.getElementById('btnScanTrigger'),
    btnExportCsv: document.getElementById('btnExportCsv'),

    // Summary Cards
    statTotalDiscovered: document.getElementById('statTotalDiscovered'),
    statOnline: document.getElementById('statOnline'),
    statOffline: document.getElementById('statOffline'),
    statTrusted: document.getElementById('statTrusted'),
    statUnknown: document.getElementById('statUnknown'),
    statBlocked: document.getElementById('statBlocked'),
    statLastScan: document.getElementById('statLastScan'),
    statEngineUsed: document.getElementById('statEngineUsed'),
    statRouterStatus: document.getElementById('statRouterStatus'),
    statRouterModel: document.getElementById('statRouterModel'),

    // Banners & Filters
    noticeContainer: document.getElementById('noticeBannerContainer'),
    filterPills: document.querySelectorAll('.filter-pill'),
    searchInput: document.getElementById('searchInput'),
    deviceTableBody: document.getElementById('deviceTableBody'),

    // Counts
    countAll: document.getElementById('countAll'),
    countOnline: document.getElementById('countOnline'),
    countOffline: document.getElementById('countOffline'),
    countUnknown: document.getElementById('countUnknown'),
    countTrusted: document.getElementById('countTrusted'),
    countBlocked: document.getElementById('countBlocked'),

    // Modals
    deviceModal: document.getElementById('deviceModal'),
    deviceModalContent: document.getElementById('deviceModalContent'),
    scanModal: document.getElementById('scanModal'),
    scanSubnetInput: document.getElementById('scanSubnetInput'),
    scanEngineSelect: document.getElementById('scanEngineSelect'),
    btnExecuteScan: document.getElementById('btnExecuteScan'),
    scanProgressArea: document.getElementById('scanProgressArea'),

    blockModal: document.getElementById('blockModal'),
    blockModalTitle: document.getElementById('blockModalTitle'),
    blockTargetName: document.getElementById('blockTargetName'),
    blockTargetIp: document.getElementById('blockTargetIp'),
    blockTargetMac: document.getElementById('blockTargetMac'),
    blockGuideMac: document.getElementById('blockGuideMac'),
    blockConfirmCheckbox: document.getElementById('blockConfirmCheckbox'),
    btnConfirmBlock: document.getElementById('btnConfirmBlock'),

    authModal: document.getElementById('authModal'),
    authForm: document.getElementById('authForm'),
    authUsername: document.getElementById('authUsername'),
    authPassword: document.getElementById('authPassword'),
    authActionBtn: document.getElementById('authActionBtn'),
    displayUsername: document.getElementById('displayUsername'),
    displayRole: document.getElementById('displayRole'),
    userAvatar: document.getElementById('userAvatar'),

    // Tabs
    scanHistoryBody: document.getElementById('scanHistoryBody'),
    btnRefreshHistory: document.getElementById('btnRefreshHistory'),
    btnTestRouter: document.getElementById('btnTestRouter'),
    routerRulesBody: document.getElementById('routerRulesBody'),

    // Settings
    settingsForm: document.getElementById('settingsForm'),
    settingRouterGateway: document.getElementById('settingRouterGateway'),
    settingSubnet: document.getElementById('settingSubnet'),
    settingScanInterval: document.getElementById('settingScanInterval'),
    settingLanAccess: document.getElementById('settingLanAccess'),
    lanAccessDetails: document.getElementById('lanAccessDetails'),
    lanUrlLink: document.getElementById('lanUrlLink'),
    btnBackupDb: document.getElementById('btnBackupDb'),
    toastContainer: document.getElementById('toastContainer'),

    // Analytics & Graphs Elements
    connectionTimelineChart: document.getElementById('connectionTimelineChart'),
    trafficUtilizationChart: document.getElementById('trafficUtilizationChart'),
    fullConnectionTimelineChart: document.getElementById('fullConnectionTimelineChart'),
    fullTrafficUtilizationChart: document.getElementById('fullTrafficUtilizationChart'),
    btnRefreshAnalytics: document.getElementById('btnRefreshAnalytics')
  };

  // Helper: Read cookie by name
  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
  }

  // Helper: Toast Notifications
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type === 'error' ? 'error' : 'success'}`;
    toast.innerHTML = `<span>${message}</span>`;
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // Helper: Secure API Request wrapper with CSRF
  async function apiRequest(url, options = {}) {
    options.headers = options.headers || {};
    const method = (options.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'DELETE'].includes(method)) {
      const csrf = state.auth.csrfToken || getCookie('netsentinel_csrf') || 'netsentinel-local-csrf';
      options.headers['X-CSRF-Token'] = csrf;
    }
    const response = await fetch(url, options);
    if (response.status === 401) {
      openAuthModal();
      throw new Error('Authentication required.');
    }
    return response;
  }

  // Format Timestamps to Local Time
  function formatLocalTime(isoStr) {
    if (!isoStr) return 'Unavailable';
    try {
      const d = new Date(isoStr);
      return d.toLocaleString(undefined, {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
      });
    } catch (e) {
      return isoStr;
    }
  }

  // Tab Navigation
  function initNavigation() {
    el.navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const tab = item.dataset.tab;
        switchTab(tab);
        if (window.innerWidth <= 768) {
          el.sidebar.classList.remove('open');
        }
      });
    });

    if (el.mobileMenuBtn) {
      el.mobileMenuBtn.addEventListener('click', () => {
        el.sidebar.classList.toggle('open');
      });
    }
  }

  function switchTab(tabId) {
    el.navItems.forEach(item => {
      item.classList.toggle('active', item.dataset.tab === tabId);
    });
    el.tabPanes.forEach(pane => {
      pane.classList.toggle('active', pane.id === `tab-${tabId}`);
    });

    const titles = {
      dashboard: 'Network Overview',
      devices: 'Devices Inventory',
      history: 'Scan History',
      analytics: 'Network Visual Analytics',
      router: 'Router Control (DBC HGU-V210-4AC)',
      settings: 'Settings & Administration'
    };
    el.pageTitle.textContent = titles[tabId] || 'Net Sentinel';

    if (tabId === 'history') loadScanHistory();
    if (tabId === 'analytics') loadAnalytics();
    if (tabId === 'router') loadRouterStatus();
    if (tabId === 'settings') loadSettings();
  }

  // Load Dashboard Summary
  async function loadSummary() {
    try {
      const res = await fetch('/api/summary');
      if (!res.ok) return;
      const data = await res.json();
      state.summary = data;

      // Update 8 Cards
      el.statTotalDiscovered.textContent = data.total_discovered;
      el.statOnline.textContent = data.online_devices;
      el.statOffline.textContent = data.offline_devices;
      el.statTrusted.textContent = data.trusted_devices;
      el.statUnknown.textContent = data.unknown_devices;
      el.statBlocked.textContent = data.blocked_devices;

      if (data.most_recent_scan) {
        el.statLastScan.textContent = formatLocalTime(data.most_recent_scan.end_time || data.most_recent_scan.start_time);
        el.statEngineUsed.textContent = `Engine: ${data.most_recent_scan.engine_used}`;
      } else {
        el.statLastScan.textContent = 'None Recorded';
        el.statEngineUsed.textContent = 'Run your first scan';
      }

      el.statRouterStatus.textContent = data.router_status === 'online' ? 'Connected' : 'Reachable (Web)';
      el.statRouterStatus.className = `stat-value-sm ${data.router_status === 'online' ? 'text-emerald-600' : 'text-slate-700'}`;
      el.statRouterModel.textContent = `${data.router_model} (${data.router_gateway})`;

      if (el.scanSubnetInput && data.current_subnet) {
        el.scanSubnetInput.value = data.current_subnet;
      }

      // Nmap notice banner if Nmap is not installed
      renderNmapNotice(data.nmap_installed);
    } catch (err) {
      console.error('Failed to load summary:', err);
    }
  }

  function renderNmapNotice(nmapInstalled) {
    if (nmapInstalled) {
      el.noticeContainer.innerHTML = '';
      return;
    }
    el.noticeContainer.innerHTML = `
      <div class="notice-banner notice-warning">
        <div class="flex items-center space-x-2">
          <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <span><strong>Nmap not detected in PATH:</strong> Net Sentinel is operating via high-speed native Windows ARP & ICMP host discovery. All devices and MACs are actively discovered.</span>
        </div>
      </div>
    `;
  }

  // Load Devices List
  async function loadDevices() {
    try {
      const res = await fetch('/api/devices');
      if (!res.ok) return;
      state.devices = await res.json();
      updatePillCounts();
      renderDeviceTable();
    } catch (err) {
      console.error('Failed to load devices:', err);
    }
  }

  function updatePillCounts() {
    const d = state.devices;
    el.countAll.textContent = d.length;
    el.countOnline.textContent = d.filter(x => x.status === 'online').length;
    el.countOffline.textContent = d.filter(x => x.status === 'offline').length;
    el.countUnknown.textContent = d.filter(x => x.classification === 'unknown').length;
    el.countTrusted.textContent = d.filter(x => x.classification === 'trusted').length;
    el.countBlocked.textContent = d.filter(x => ['blocked', 'manual_rule'].includes(x.block_status)).length;
  }

  function filterDevices() {
    let list = state.devices;
    const filter = state.activeFilter;
    const q = state.searchQuery.toLowerCase().trim();

    if (filter === 'online') list = list.filter(x => x.status === 'online');
    else if (filter === 'offline') list = list.filter(x => x.status === 'offline');
    else if (filter === 'unknown') list = list.filter(x => x.classification === 'unknown');
    else if (filter === 'trusted') list = list.filter(x => x.classification === 'trusted');
    else if (filter === 'blocked') list = list.filter(x => ['blocked', 'manual_rule'].includes(x.block_status));

    if (q) {
      list = list.filter(x =>
        (x.ip_address && x.ip_address.toLowerCase().includes(q)) ||
        (x.mac_address && x.mac_address.toLowerCase().includes(q)) ||
        (x.hostname && x.hostname.toLowerCase().includes(q)) ||
        (x.custom_name && x.custom_name.toLowerCase().includes(q)) ||
        (x.vendor && x.vendor.toLowerCase().includes(q))
      );
    }
    return list;
  }

  function renderDeviceTable() {
    const devices = filterDevices();
    if (devices.length === 0) {
      el.deviceTableBody.innerHTML = `
        <tr>
          <td colspan="9" class="text-center py-8 text-slate-400">
            No devices found matching filter "${state.activeFilter}".
          </td>
        </tr>
      `;
      return;
    }

    el.deviceTableBody.innerHTML = devices.map(d => {
      const isOnline = d.status === 'online';
      const statusPill = isOnline
        ? `<span class="status-pill status-online"><span class="dot"></span> Online</span>`
        : `<span class="status-pill status-offline"><span class="dot"></span> Offline</span>`;

      const classBadge = d.classification === 'trusted'
        ? `<span class="badge badge-trusted">Trusted</span>`
        : `<span class="badge badge-unknown">Unknown</span>`;

      let blockBadge = `<span class="text-xs text-slate-400 font-medium">None</span>`;
      if (d.block_status === 'blocked') {
        blockBadge = `<span class="badge badge-blocked">Blocked</span>`;
      } else if (d.block_status === 'manual_rule') {
        blockBadge = `<span class="badge badge-blocked">Manual Rule</span>`;
      }

      const displayName = d.custom_name || d.hostname || (d.is_gateway ? 'Default Gateway Router' : (d.is_host ? 'Host Laptop (This Machine)' : 'Unlabeled Device'));
      const subLabel = d.custom_name && d.hostname ? `<span class="text-xs text-slate-400 block">${d.hostname}</span>` : '';
      const tagChip = d.is_gateway
        ? `<span class="badge bg-purple-100 text-purple-700 ml-1">Gateway</span>`
        : (d.is_host ? `<span class="badge bg-blue-100 text-blue-700 ml-1">This Host</span>` : '');

      return `
        <tr data-id="${d.id}">
          <td>
            <div class="font-semibold text-slate-800">${escapeHtml(displayName)} ${tagChip}</div>
            ${subLabel}
            <span class="text-xs text-slate-400">${escapeHtml(d.device_type || 'Unclassified')}</span>
          </td>
          <td class="font-mono font-medium">${d.ip_address}</td>
          <td class="font-mono text-slate-600">${d.mac_address || '<span class="text-slate-400">Unavailable</span>'}</td>
          <td class="text-slate-700">${escapeHtml(d.vendor || 'Unknown Vendor')}</td>
          <td>${classBadge}</td>
          <td>${statusPill}</td>
          <td class="text-xs text-slate-500">${formatLocalTime(d.last_seen)}</td>
          <td>${blockBadge}</td>
          <td class="text-right">
            <div class="flex justify-end space-x-2">
              <button class="btn btn-sm btn-outline btn-details" data-id="${d.id}" title="View Details">Details</button>
              ${d.classification === 'trusted'
                ? `<button class="btn btn-sm btn-outline btn-untrust" data-id="${d.id}" title="Mark Unknown">Untrust</button>`
                : `<button class="btn btn-sm btn-outline btn-trust" data-id="${d.id}" title="Mark Trusted">Trust</button>`
              }
              ${d.block_status === 'unblocked'
                ? `<button class="btn btn-sm btn-danger btn-block-action" data-id="${d.id}" data-action="block">Block</button>`
                : `<button class="btn btn-sm btn-outline btn-block-action text-emerald-600" data-id="${d.id}" data-action="unblock">Unblock</button>`
              }
            </div>
          </td>
        </tr>
      `;
    }).join('');

    attachTableActionListeners();
  }

  function attachTableActionListeners() {
    // Details
    document.querySelectorAll('.btn-details').forEach(btn => {
      btn.addEventListener('click', () => openDeviceModal(parseInt(btn.dataset.id)));
    });

    // Trust / Untrust
    document.querySelectorAll('.btn-trust').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          const res = await apiRequest(`/api/devices/${btn.dataset.id}/trust`, { method: 'POST' });
          if (res.ok) {
            showToast('Device marked as Trusted.', 'success');
            await loadDevices();
            await loadSummary();
          }
        } catch (e) {
          showToast(e.message, 'error');
        }
      });
    });

    document.querySelectorAll('.btn-untrust').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          const res = await apiRequest(`/api/devices/${btn.dataset.id}/unknown`, { method: 'POST' });
          if (res.ok) {
            showToast('Device marked as Unknown.', 'success');
            await loadDevices();
            await loadSummary();
          }
        } catch (e) {
          showToast(e.message, 'error');
        }
      });
    });

    // Block / Unblock modal trigger
    document.querySelectorAll('.btn-block-action').forEach(btn => {
      btn.addEventListener('click', () => {
        const devId = parseInt(btn.dataset.id);
        const action = btn.dataset.action;
        const target = state.devices.find(x => x.id === devId);
        if (target) {
          openBlockModal(target, action);
        }
      });
    });
  }

  // Device Details Modal
  async function openDeviceModal(deviceId) {
    try {
      const res = await fetch(`/api/devices/${deviceId}`);
      if (!res.ok) return;
      const device = await res.json();
      state.currentDevice = device;

      document.getElementById('modalDeviceTitle').textContent =
        device.custom_name || device.hostname || `Device #${device.id}`;

      let observationsHtml = '';
      if (device.observations && device.observations.length > 0) {
        observationsHtml = `
          <h4 class="text-xs font-semibold uppercase text-slate-500 mt-4 mb-2">Historical Observations (${device.observations.length})</h4>
          <div class="table-container max-h-48 overflow-y-auto">
            <table class="device-table">
              <thead><tr><th>Timestamp</th><th>IP</th><th>MAC</th><th>Latency</th></tr></thead>
              <tbody>
                ${device.observations.map(o => `
                  <tr>
                    <td class="text-xs">${formatLocalTime(o.timestamp)}</td>
                    <td class="font-mono text-xs">${o.ip_address}</td>
                    <td class="font-mono text-xs">${o.mac_address || '--'}</td>
                    <td class="text-xs">${o.response_time_ms ? o.response_time_ms + ' ms' : '--'}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        `;
      }

      el.deviceModalContent.innerHTML = `
        <div class="grid grid-cols-2 gap-4 text-xs bg-slate-50 p-4 rounded-lg border border-slate-200">
          <div><span class="text-slate-400">IP Address:</span> <strong class="font-mono text-slate-700 block">${device.ip_address}</strong></div>
          <div><span class="text-slate-400">MAC Address:</span> <strong class="font-mono text-slate-700 block">${device.mac_address || 'Unavailable'}</strong></div>
          <div><span class="text-slate-400">Vendor:</span> <strong class="text-slate-700 block">${escapeHtml(device.vendor || 'Unknown')}</strong></div>
          <div><span class="text-slate-400">Device Category:</span> <strong class="text-slate-700 block">${escapeHtml(device.device_type)}</strong></div>
          <div><span class="text-slate-400">First Seen:</span> <span class="text-slate-600 block">${formatLocalTime(device.first_seen)}</span></div>
          <div><span class="text-slate-400">Last Seen:</span> <span class="text-slate-600 block">${formatLocalTime(device.last_seen)}</span></div>
        </div>

        <form id="deviceEditForm" class="space-y-3 pt-2">
          <div>
            <label class="block text-xs font-semibold uppercase text-slate-500 mb-1">Custom Device Label</label>
            <input type="text" id="editCustomName" class="input-field" value="${escapeHtml(device.custom_name || '')}" placeholder="e.g. Living Room Smart TV">
          </div>
          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-500 mb-1">Classification</label>
              <select id="editClassification" class="input-field">
                <option value="unknown" ${device.classification === 'unknown' ? 'selected' : ''}>Unknown</option>
                <option value="trusted" ${device.classification === 'trusted' ? 'selected' : ''}>Trusted</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-semibold uppercase text-slate-500 mb-1">Category</label>
              <input type="text" id="editDeviceType" class="input-field" value="${escapeHtml(device.device_type || '')}">
            </div>
          </div>
          <div>
            <label class="block text-xs font-semibold uppercase text-slate-500 mb-1">Notes</label>
            <textarea id="editNotes" class="input-field" rows="2" placeholder="Add operational notes...">${escapeHtml(device.notes || '')}</textarea>
          </div>
          <div class="flex justify-end space-x-2 pt-2">
            <button type="submit" class="btn btn-primary btn-sm">Save Changes</button>
          </div>
        </form>

        ${observationsHtml}
      `;

      document.getElementById('deviceEditForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
          custom_name: document.getElementById('editCustomName').value,
          classification: document.getElementById('editClassification').value,
          device_type: document.getElementById('editDeviceType').value,
          notes: document.getElementById('editNotes').value
        };

        try {
          const updateRes = await apiRequest(`/api/devices/${device.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          if (updateRes.ok) {
            showToast('Device updated successfully.', 'success');
            closeModal(el.deviceModal);
            await loadDevices();
            await loadSummary();
          } else {
            const err = await updateRes.json();
            showToast(err.detail || 'Update failed', 'error');
          }
        } catch (err) {
          showToast(err.message, 'error');
        }
      });

      openModal(el.deviceModal);
    } catch (e) {
      console.error(e);
    }
  }

  // Scan Network Modal
  function initScanControls() {
    el.btnScanTrigger.addEventListener('click', () => {
      openModal(el.scanModal);
    });

    el.btnExecuteScan.addEventListener('click', async () => {
      const subnet = el.scanSubnetInput.value.trim();
      const engine = el.scanEngineSelect.value;

      el.scanProgressArea.classList.remove('hidden');
      el.btnExecuteScan.disabled = true;

      try {
        const res = await apiRequest('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subnet: subnet || null, engine_preference: engine })
        });
        const result = await res.json();
        if (res.ok) {
          showToast(`Scan complete: Discovered ${result.data.devices_found} devices (${result.data.new_devices} new).`, 'success');
          closeModal(el.scanModal);
          await loadDevices();
          await loadSummary();
          await loadAnalytics();
        } else {
          showToast(result.detail || 'Scan failed', 'error');
        }
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        el.scanProgressArea.classList.add('hidden');
        el.btnExecuteScan.disabled = false;
      }
    });
  }

  // Block / Unblock Modal
  function openBlockModal(device, action) {
    state.blockTargetDevice = { device, action };
    el.blockModalTitle.textContent = action === 'block' ? 'Confirm Router Access Control Restriction' : 'Confirm Router Unblock';
    el.blockModalTitle.className = `modal-title ${action === 'block' ? 'text-rose-600' : 'text-emerald-600'}`;
    el.btnConfirmBlock.textContent = action === 'block' ? 'Apply Block Rule' : 'Remove Restriction';
    el.btnConfirmBlock.className = `btn ${action === 'block' ? 'btn-danger' : 'btn-primary'}`;

    el.blockTargetName.textContent = device.custom_name || device.hostname || `Device #${device.id}`;
    el.blockTargetIp.textContent = device.ip_address;
    el.blockTargetMac.textContent = device.mac_address || 'Unavailable';
    el.blockGuideMac.textContent = device.mac_address || 'Unavailable';
    el.blockConfirmCheckbox.checked = false;

    openModal(el.blockModal);
  }

  function initBlockControls() {
    el.btnConfirmBlock.addEventListener('click', async () => {
      if (!el.blockConfirmCheckbox.checked) {
        showToast('Please check the confirmation box before proceeding.', 'error');
        return;
      }

      const { device, action } = state.blockTargetDevice;
      const endpoint = action === 'block' ? '/api/router/block' : '/api/router/unblock';
      const payload = {
        mac_address: device.mac_address,
        ip_address: device.ip_address,
        device_name: device.custom_name || device.hostname,
        confirmed: true
      };

      try {
        const res = await apiRequest(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const result = await res.json();
        if (res.ok) {
          showToast(result.message || 'Action recorded successfully.', 'success');
          closeModal(el.blockModal);
          await loadDevices();
          await loadSummary();
        } else {
          showToast(result.detail || result.error || 'Action failed.', 'error');
        }
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  }

  // Scan History Loader
  async function loadScanHistory() {
    try {
      const res = await fetch('/api/scan/history');
      if (!res.ok) return;
      const history = await res.json();
      if (history.length === 0) {
        el.scanHistoryBody.innerHTML = `<tr><td colspan="9" class="text-center py-6 text-slate-400">No scans recorded yet.</td></tr>`;
        return;
      }
      el.scanHistoryBody.innerHTML = history.map(h => `
        <tr>
          <td class="font-mono">#${h.id}</td>
          <td>${formatLocalTime(h.start_time)}</td>
          <td>${h.end_time ? 'Completed' : 'Running'}</td>
          <td class="font-mono text-xs">${h.subnet}</td>
          <td><span class="badge bg-slate-100 text-slate-700">${h.engine_used}</span></td>
          <td class="font-semibold">${h.devices_found}</td>
          <td class="text-emerald-600 font-semibold">+${h.new_devices}</td>
          <td class="text-slate-400 font-semibold">${h.offline_devices}</td>
          <td><span class="badge ${h.status === 'completed' ? 'badge-trusted' : 'badge-blocked'}">${h.status}</span></td>
        </tr>
      `).join('');
    } catch (e) {
      console.error(e);
    }
  }

  // Analytics & Visual Graphs Loader
  async function loadAnalytics() {
    await Promise.all([
      loadConnectionTimeline(),
      loadNetworkUtilization()
    ]);
  }

  async function loadConnectionTimeline() {
    try {
      const res = await fetch('/api/analytics/connection-timeline');
      if (!res.ok) return;
      const data = await res.json();
      renderTimelineGraph(data, el.connectionTimelineChart, 5);
      if (el.fullConnectionTimelineChart) {
        renderTimelineGraph(data, el.fullConnectionTimelineChart, 25);
      }
    } catch (e) {
      console.error('Failed to load connection timeline:', e);
    }
  }

  function renderTimelineGraph(data, container, maxItems = 5) {
    if (!container) return;
    if (!data || data.length === 0) {
      container.innerHTML = '<div class="text-center py-8 text-slate-400 text-xs">No connection timeline records yet. Run a network scan.</div>';
      return;
    }

    const items = data.slice(0, maxItems);
    container.innerHTML = items.map(item => {
      const isOnline = item.status === 'online';
      const firstSeen = formatLocalTime(item.first_seen);
      const lastSeen = formatLocalTime(item.last_seen);
      const pingTime = (item.connection_points && item.connection_points.length > 0 && item.connection_points[0].latency_ms)
        ? item.connection_points[0].latency_ms + ' ms'
        : (isOnline ? '0.4 ms' : 'Offline');

      return `
        <div class="timeline-item">
          <div class="timeline-device-info">
            <div class="timeline-device-name" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</div>
            <div class="timeline-device-meta">${item.ip_address}</div>
          </div>
          <div class="timeline-track-container">
            <div class="timeline-track">
              <div class="timeline-fill" style="width: ${isOnline ? '100%' : '50%'}; background: ${isOnline ? 'linear-gradient(90deg, #38bdf8 0%, #0284c7 100%)' : '#cbd5e1'};"></div>
            </div>
            <div class="timeline-time-labels">
              <span>First: ${firstSeen}</span>
              <span>Active: ${lastSeen} (${pingTime})</span>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  async function loadNetworkUtilization() {
    try {
      const res = await fetch('/api/analytics/network-utilization');
      if (!res.ok) return;
      const data = await res.json();
      renderUtilizationGraph(data, el.trafficUtilizationChart, 5);
      if (el.fullTrafficUtilizationChart) {
        renderUtilizationGraph(data, el.fullTrafficUtilizationChart, 20);
      }
    } catch (e) {
      console.error('Failed to load network utilization:', e);
    }
  }

  function renderUtilizationGraph(data, container, maxItems = 5) {
    if (!container) return;
    if (!data || data.length === 0) {
      container.innerHTML = '<div class="text-center py-8 text-slate-400 text-xs">No utilization records available.</div>';
      return;
    }

    const items = data.slice(0, maxItems);
    const maxVal = Math.max(...data.map(x => x.usage_gb)) || 150;

    container.innerHTML = items.map(item => {
      const pct = Math.min(100, Math.round((item.usage_gb / maxVal) * 100));
      let badgeStyle = 'background-color: #ecfdf5; color: #065f46; border: 1px solid #a7f3d0;';
      if (item.usage_level === 'high') {
        badgeStyle = 'background-color: #fef2f2; color: #991b1b; border: 1px solid #fecaca;';
      } else if (item.usage_level === 'moderate') {
        badgeStyle = 'background-color: #fff7ed; color: #9a3412; border: 1px solid #fed7aa;';
      }

      return `
        <div class="utilization-row">
          <div class="utilization-header">
            <div class="utilization-title">
              <span class="utilization-name">${escapeHtml(item.name)}</span>
              <span class="utilization-mac font-mono">${item.mac_address}</span>
            </div>
            <div class="utilization-metrics">
              <span class="utilization-val" style="color: ${item.color};">${item.usage_gb} GB</span>
              <span class="utilization-badge" style="${badgeStyle}">${item.label}</span>
            </div>
          </div>
          <div class="utilization-track">
            <div class="utilization-bar-fill" style="width: ${pct}%; background-color: ${item.color};"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Router Control Tab Loader
  async function loadRouterStatus() {
    try {
      const res = await fetch('/api/router/status');
      if (!res.ok) return;
      const data = await res.json();
      document.getElementById('routerModelName').textContent = data.router_model;
      document.getElementById('routerServerHeader').textContent = data.capabilities.server_header || 'Embedded Web Server';
      document.getElementById('routerAutoStatus').textContent = data.capabilities.automated_api_verified ? 'Automated Verified' : 'Guided Manual Workflow (Blacklist)';

      if (data.active_rules && data.active_rules.length > 0) {
        el.routerRulesBody.innerHTML = data.active_rules.map(r => `
          <tr>
            <td class="text-xs text-slate-500">${formatLocalTime(r.timestamp)}</td>
            <td class="font-mono font-bold">${r.mac_address}</td>
            <td class="font-mono text-xs">${r.ip_address || '--'}</td>
            <td><span class="badge badge-blocked">${r.action}</span></td>
            <td><span class="badge ${r.status === 'verified' ? 'badge-trusted' : 'badge-unknown'}">${r.status}</span></td>
            <td class="text-xs text-slate-600">${escapeHtml(r.details || '')}</td>
          </tr>
        `).join('');
      } else {
        el.routerRulesBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-slate-400">No active router rules registered.</td></tr>`;
      }
    } catch (e) {
      console.error(e);
    }
  }

  // Settings Tab Loader
  async function loadSettings() {
    try {
      const res = await fetch('/api/settings');
      if (!res.ok) return;
      const s = await res.json();
      state.settings = s;

      el.settingRouterGateway.value = s.router_gateway || '192.168.1.1';
      el.settingSubnet.value = s.current_subnet || '192.168.1.0/24';
      el.settingScanInterval.value = s.scan_interval_minutes || 15;
      el.settingLanAccess.checked = s.lan_access_enabled;
      el.settingAppVersion.textContent = `${s.app_name} v${s.app_version} by ${s.developer}`;

      if (s.lan_access_enabled) {
        el.lanAccessDetails.classList.remove('hidden');
        el.lanUrlLink.href = s.lan_access_url;
        el.lanUrlLink.textContent = s.lan_access_url;
      } else {
        el.lanAccessDetails.classList.add('hidden');
      }
    } catch (e) {
      console.error(e);
    }
  }

  function initSettingsControls() {
    el.settingsForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        router_gateway: el.settingRouterGateway.value,
        subnet: el.settingSubnet.value,
        scan_interval_minutes: parseInt(el.settingScanInterval.value),
        lan_access_enabled: el.settingLanAccess.checked
      };

      try {
        const res = await apiRequest('/api/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (res.ok) {
          showToast('Settings saved successfully.', 'success');
          await loadSettings();
        } else {
          const err = await res.json();
          showToast(err.detail || 'Failed to save settings', 'error');
        }
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    el.btnBackupDb.addEventListener('click', async () => {
      try {
        const res = await apiRequest('/api/settings/backup', { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
          showToast(`SQLite backup created: ${data.backup_filename}`, 'success');
        } else {
          showToast('Backup failed.', 'error');
        }
      } catch (e) {
        showToast(e.message, 'error');
      }
    });
  }

  // Authentication & First-Run Wizard
  async function checkAuthStatus() {
    try {
      const res = await fetch('/api/auth/status');
      if (!res.ok) return;
      const data = await res.json();
      state.auth = data;

      if (!data.admin_exists) {
        // First run wizard
        openAuthModal(true);
      } else if (data.authenticated) {
        el.displayUsername.textContent = data.username;
        el.displayRole.textContent = 'Administrator';
        el.userAvatar.textContent = data.username.charAt(0).toUpperCase();
        el.authActionBtn.title = 'Sign Out';
      } else {
        el.displayUsername.textContent = 'Guest';
        el.displayRole.textContent = 'Read-Only Mode';
        el.userAvatar.textContent = 'G';
        el.authActionBtn.title = 'Sign In';
      }
    } catch (e) {
      console.error(e);
    }
  }

  function openAuthModal(isFirstRun = false) {
    const title = document.getElementById('authModalTitle');
    const desc = document.getElementById('authModalDesc');
    const submitBtn = document.getElementById('btnAuthSubmit');

    if (isFirstRun) {
      title.textContent = 'Welcome: Create Admin Password';
      desc.textContent = 'Set up your local administrator password to secure Net Sentinel controls.';
      submitBtn.textContent = 'Initialize Account';
      el.authUsername.value = 'admin';
    } else {
      title.textContent = 'Sign In to Net Sentinel';
      desc.textContent = 'Enter your administrator credentials to make configuration changes.';
      submitBtn.textContent = 'Sign In';
    }
    openModal(el.authModal);
  }

  function initAuthControls() {
    el.authActionBtn.addEventListener('click', async () => {
      if (state.auth.authenticated) {
        await fetch('/api/auth/logout', { method: 'POST' });
        showToast('Logged out.', 'info');
        await checkAuthStatus();
      } else {
        openAuthModal(!state.auth.admin_exists);
      }
    });

    el.authForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = el.authUsername.value.trim();
      const password = el.authPassword.value;
      const isFirstRun = !state.auth.admin_exists;
      const endpoint = isFirstRun ? '/api/auth/setup' : '/api/auth/login';

      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(isFirstRun ? 'Admin setup complete!' : 'Signed in successfully!', 'success');
          closeModal(el.authModal);
          await checkAuthStatus();
        } else {
          showToast(data.detail || 'Authentication failed', 'error');
        }
      } catch (err) {
        showToast(err.message, 'error');
      }
    });
  }

  // Modals management
  function openModal(modalEl) {
    if (modalEl) modalEl.classList.add('open');
  }
  function closeModal(modalEl) {
    if (modalEl) modalEl.classList.remove('open');
  }

  function initModals() {
    document.querySelectorAll('[data-close]').forEach(btn => {
      btn.addEventListener('click', () => {
        const modalId = btn.dataset.close;
        const modal = document.getElementById(modalId);
        if (modal) closeModal(modal);
      });
    });

    // Close on backdrop click
    document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
      backdrop.addEventListener('click', (e) => {
        if (e.target === backdrop) closeModal(backdrop);
      });
    });
  }

  // Search & Filter listeners
  function initFilterControls() {
    el.filterPills.forEach(pill => {
      pill.addEventListener('click', () => {
        el.filterPills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        state.activeFilter = pill.dataset.filter;
        renderDeviceTable();
      });
    });

    el.searchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value;
      renderDeviceTable();
    });

    el.btnRefresh.addEventListener('click', async () => {
      showToast('Refreshing network device status...', 'info');
      await loadSummary();
      await loadDevices();
      await loadAnalytics();
    });

    el.btnExportCsv.addEventListener('click', () => {
      window.location.href = '/api/devices/export/csv';
    });

    if (el.btnRefreshHistory) {
      el.btnRefreshHistory.addEventListener('click', loadScanHistory);
    }
    if (el.btnRefreshAnalytics) {
      el.btnRefreshAnalytics.addEventListener('click', loadAnalytics);
    }
    if (el.btnTestRouter) {
      el.btnTestRouter.addEventListener('click', async () => {
        showToast('Inspecting router management interface at 192.168.1.1...', 'info');
        await loadRouterStatus();
      });
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Initialize Application
  async function init() {
    initNavigation();
    initModals();
    initFilterControls();
    initScanControls();
    initBlockControls();
    initSettingsControls();
    initAuthControls();

    await checkAuthStatus();
    await loadSummary();
    await loadDevices();
    await loadAnalytics();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
