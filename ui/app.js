const tauri = window.__TAURI__;
const invoke = tauri?.core?.invoke;
const listen = tauri?.event?.listen;

const appState = {
  passwords: [],
  allProtocols: [],
  selectedProtocols: new Set(),
  queuedSources: [],
  trackedFolderPath: null,
  trackedIncludeSubfolders: false,
  lastResult: null,
  activePreviewTab: 'ppanel-xray',
  theme: 'system',
};

const $ = (id) => document.getElementById(id);

function showAlert(msg) {
  const el = $('global-alert');
  el.textContent = msg;
  el.hidden = false;
}

function clearAlert() {
  const el = $('global-alert');
  el.textContent = '';
  el.hidden = true;
}

function formatBytes(bytes) {
  if (!bytes || bytes < 1024) return `${bytes || 0} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

// ---------------- THEME ----------------
function applyTheme(pref) {
  appState.theme = pref;
  try {
    localStorage.setItem('theme-preference', pref);
  } catch (_) {}
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (meta) {
    if (pref === 'light') meta.setAttribute('content', 'light');
    else if (pref === 'dark') meta.setAttribute('content', 'dark');
    else meta.setAttribute('content', 'light dark');
  }
  document.querySelectorAll('.seg-btn[data-theme]').forEach((btn) => {
    btn.setAttribute('aria-pressed', btn.dataset.theme === pref ? 'true' : 'false');
  });
}

// ---------------- ACCESSIBLE TABS ----------------
function initTabs() {
  document.querySelectorAll('.tablist[data-tab-group]').forEach((tablist) => {
    const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
    const activateTab = (tab) => {
      tabs.forEach((t) => {
        const isTarget = t === tab;
        t.setAttribute('aria-selected', isTarget ? 'true' : 'false');
        t.tabIndex = isTarget ? 0 : -1;
        const panel = $(t.getAttribute('aria-controls'));
        if (panel) panel.hidden = !isTarget;
      });
      if (tablist.dataset.tabGroup === 'preview') {
        appState.activePreviewTab = tab.getAttribute('aria-controls');
      }
    };

    tabs.forEach((tab, idx) => {
      tab.addEventListener('click', () => activateTab(tab));
      tab.addEventListener('keydown', (e) => {
        // RTL aware navigation: ArrowLeft moves forward in RTL tabs
        let nextIdx = null;
        if (e.key === 'ArrowLeft') nextIdx = (idx + 1) % tabs.length;
        else if (e.key === 'ArrowRight') nextIdx = (idx - 1 + tabs.length) % tabs.length;
        else if (e.key === 'Home') nextIdx = 0;
        else if (e.key === 'End') nextIdx = tabs.length - 1;
        if (nextIdx !== null) {
          e.preventDefault();
          activateTab(tabs[nextIdx]);
          tabs[nextIdx].focus();
        }
      });
    });
  });
}

// ---------------- DIALOGS ----------------
function setupDialogCloseCleanup(dialog) {
  dialog.addEventListener('close', () => {
    dialog.returnValue = '';
  });
  // Light-dismiss fallback if browser lacks closedby="any"
  dialog.addEventListener('click', (e) => {
    if (typeof dialog.closedBy === 'undefined' && e.target === dialog) {
      dialog.close();
    }
  });
}

function askConfirm(message) {
  return new Promise((resolve) => {
    const dlg = $('dialog-confirm');
    $('confirm-dialog-message').textContent = message;
    const onClose = () => {
      const ok = dlg.returnValue === 'confirm';
      dlg.removeEventListener('close', onClose);
      resolve(ok);
    };
    dlg.addEventListener('close', onClose);
    dlg.showModal();
  });
}

// ---------------- PROTOCOL CHIPS ----------------
function renderProtocolChips() {
  const container = $('protocols-chip-grid');
  container.innerHTML = '';
  for (const proto of appState.allProtocols) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'proto-chip';
    btn.textContent = proto;
    const active = appState.selectedProtocols.has(proto);
    btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    btn.addEventListener('click', () => {
      if (appState.selectedProtocols.has(proto)) appState.selectedProtocols.delete(proto);
      else appState.selectedProtocols.add(proto);
      btn.setAttribute('aria-pressed', appState.selectedProtocols.has(proto) ? 'true' : 'false');
      $('proto-active-count').textContent = String(appState.selectedProtocols.size);
      persistCurrentSettings();
    });
    container.appendChild(btn);
  }
  $('proto-active-count').textContent = String(appState.selectedProtocols.size);
}

// ---------------- QUEUE MANAGEMENT ----------------
function addSourcesToQueue(entries) {
  const existingIds = new Set(appState.queuedSources.map((s) => s.id));
  let added = 0;
  for (const e of entries) {
    if (!existingIds.has(e.id)) {
      appState.queuedSources.push(e);
      existingIds.add(e.id);
      added++;
    }
  }
  renderQueue();
  return added;
}

function renderQueue() {
  const count = appState.queuedSources.length;
  $('queued-count-label').textContent = `${count} فایل در صف`;
  $('btn-clear-queue').hidden = count === 0;
  $('queued-list-container').hidden = count === 0;

  const list = $('queued-files-list');
  list.innerHTML = '';
  let totalSize = 0;
  appState.queuedSources.forEach((src, index) => {
    totalSize += src.size || 0;
    const li = document.createElement('li');
    li.className = 'queued-item';
    const nameSpan = document.createElement('span');
    nameSpan.className = 'queued-name';
    nameSpan.textContent = src.path || src.name;
    nameSpan.title = src.path || src.name;

    const rightWrap = document.createElement('div');
    rightWrap.style.display = 'inline-flex';
    rightWrap.style.alignItems = 'center';
    rightWrap.style.gap = '8px';

    const sizeSpan = document.createElement('span');
    sizeSpan.className = 'muted-text ltr-inline';
    sizeSpan.textContent = formatBytes(src.size);

    const rmBtn = document.createElement('button');
    rmBtn.type = 'button';
    rmBtn.className = 'text-btn danger-text';
    rmBtn.textContent = 'حذف';
    rmBtn.addEventListener('click', () => {
      appState.queuedSources.splice(index, 1);
      renderQueue();
    });

    rightWrap.append(sizeSpan, rmBtn);
    li.append(nameSpan, rightWrap);
    list.appendChild(li);
  });

  $('queued-meta').textContent = count > 0 ? `حجم کل: ${formatBytes(totalSize)}` : '';
}

// ---------------- PASSWORD VAULT ----------------
function renderVaultList() {
  $('vault-count-badge').textContent = String(appState.passwords.length);
  const list = $('vault-list');
  list.innerHTML = '';
  if (appState.passwords.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'muted-text';
    empty.textContent = 'هنوز هیچ رمزی در مخزن ذخیره نشده است.';
    list.appendChild(empty);
    return;
  }
  appState.passwords.forEach((pw, idx) => {
    const li = document.createElement('li');
    li.className = 'vault-row';
    const span = document.createElement('span');
    span.className = 'ltr-input';
    span.textContent = pw;
    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'text-btn danger-text';
    delBtn.textContent = 'حذف';
    delBtn.addEventListener('click', () => {
      appState.passwords.splice(idx, 1);
      renderVaultList();
      persistCurrentSettings();
    });
    li.append(span, delBtn);
    list.appendChild(li);
  });
}

// ---------------- SETTINGS COLLECTION ----------------
function collectOptions() {
  return {
    filterDuplicates: $('chk-filter-dups').checked,
    filterBroken: $('chk-filter-broken').checked,
    ignoreExpired: $('chk-ignore-expired').checked,
    limitMaxConfigs: $('chk-limit-max').checked,
    maxConfigsCount: Math.max(1, parseInt($('input-max-configs').value, 10) || 500),
    allowedProtocols: Array.from(appState.selectedProtocols),
    outputScope: {
      mixAll: $('chk-scope-mix').checked,
      perSource: $('chk-scope-persrc').checked,
    },
    outputFormats: {
      xray: $('chk-fmt-xray').checked,
      xrayBase64: $('chk-fmt-xray-b64').checked,
      singbox: $('chk-fmt-singbox').checked,
      mihomo: $('chk-fmt-mihomo').checked,
      companions: $('chk-fmt-companions').checked,
    },
    protocolSplit: {
      allProtocols: $('chk-split-all').checked,
      byProtocol: $('chk-split-byproto').checked,
    },
    outputDir: $('input-output-dir').value.trim(),
    moveDecryptedToTrash: $('chk-move-trash').checked,
    proxyMode: $('select-proxy-mode').value,
    customProxyUrl: $('input-custom-proxy').value.trim(),
  };
}

function applyOptionsToUI(opts) {
  if (!opts) return;
  $('chk-filter-dups').checked = opts.filterDuplicates ?? true;
  $('chk-filter-broken').checked = opts.filterBroken ?? true;
  $('chk-ignore-expired').checked = opts.ignoreExpired ?? true;
  $('chk-limit-max').checked = opts.limitMaxConfigs ?? false;
  $('input-max-configs').value = String(opts.maxConfigsCount ?? 500);

  if (opts.outputScope) {
    $('chk-scope-mix').checked = opts.outputScope.mixAll ?? true;
    $('chk-scope-persrc').checked = opts.outputScope.perSource ?? false;
  }
  if (opts.outputFormats) {
    $('chk-fmt-xray').checked = opts.outputFormats.xray ?? true;
    $('chk-fmt-xray-b64').checked = opts.outputFormats.xrayBase64 ?? false;
    $('chk-fmt-singbox').checked = opts.outputFormats.singbox ?? true;
    $('chk-fmt-mihomo').checked = opts.outputFormats.mihomo ?? true;
    $('chk-fmt-companions').checked = opts.outputFormats.companions ?? true;
  }
  if (opts.protocolSplit) {
    $('chk-split-all').checked = opts.protocolSplit.allProtocols ?? true;
    $('chk-split-byproto').checked = opts.protocolSplit.byProtocol ?? false;
  }
  if (opts.outputDir) $('input-output-dir').value = opts.outputDir;
  $('chk-move-trash').checked = opts.moveDecryptedToTrash ?? false;
  $('select-proxy-mode').value = opts.proxyMode || 'autoDetect';
  $('input-custom-proxy').value = opts.customProxyUrl || '';
  $('custom-proxy-wrap').hidden = $('select-proxy-mode').value !== 'custom';
}

let saveTimer = null;
function persistCurrentSettings() {
  if (!invoke) return;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    invoke('save_user_preferences', {
      payload: {
        passwords: appState.passwords,
        options: collectOptions(),
        theme: appState.theme,
        lastFolderPath: $('input-folder-path').value.trim(),
        includeSubfolders: $('chk-subfolders').checked,
      },
    }).catch(() => {});
  }, 250);
}

// ---------------- SCANNING FOLDER ----------------
async function performFolderScan(newOnly) {
  clearAlert();
  const folderPath = $('input-folder-path').value.trim();
  if (!folderPath) {
    showAlert('لطفاً ابتدا یک پوشه را انتخاب کنید.');
    return;
  }
  const includeSubfolders = $('chk-subfolders').checked;
  try {
    const scan = await invoke('scan_folder', {
      folderPath,
      includeSubfolders,
      newOnly,
    });
    appState.trackedFolderPath = scan.folderPath;
    appState.trackedIncludeSubfolders = includeSubfolders;

    // Replace queued folder files cleanly on fresh full scan, or append new files on incremental rescan
    if (!newOnly) {
      appState.queuedSources = [];
    }
    const added = addSourcesToQueue(scan.supportedFiles);

    const report = $('folder-scan-report');
    report.hidden = false;
    report.textContent = newOnly
      ? `بررسی فایل‌های جدید تکمیل شد | کل فایل‌های پوشه: ${scan.totalFilesSeen} | فایل‌های جدید اضافه‌شده به صف: ${added} | قبلاً واردشده (نادیده گرفته‌شد): ${scan.skippedAlreadyImported} | غیرپشتیبانی‌شده: ${scan.unsupportedCount}`
      : `اسکن کامل پوشه تکمیل شد | کل فایل‌ها: ${scan.totalFilesSeen} | پشتیبانی‌شده اضافه‌شده به صف: ${added} | غیرپشتیبانی‌شده: ${scan.unsupportedCount}`;
  } catch (err) {
    showAlert(String(err));
  }
}

// ---------------- RENDER RESULTS ----------------
function renderBatchResult(res) {
  appState.lastResult = res;
  $('results-section').hidden = false;

  const trashMsg =
    res.movedToTrashCount > 0
      ? ` • ${res.movedToTrashCount} فایل پردازش‌شده به سطل زباله منتقل شد`
      : '';
  $('results-subtitle').textContent = `منابع موفق: ${res.succeededSources} از ${res.totalSources} • فایل‌های خروجی ساخته‌شده: ${res.writtenFiles.length}${trashMsg}`;

  $('kpi-total').textContent = String(res.stats.total);
  $('kpi-valid').textContent = String(res.stats.valid);
  $('kpi-dups').textContent = String(res.stats.duplicates);
  $('kpi-rejected').textContent = String(res.stats.rejected);
  $('kpi-expired').textContent = String(res.stats.expiredCount);

  const protoStrip = $('proto-stats-strip');
  protoStrip.innerHTML = '';
  const entries = Object.entries(res.stats.protoCounts || {});
  entries.forEach(([k, v]) => {
    const span = document.createElement('span');
    span.className = 'stat-badge ltr-inline';
    span.textContent = `${k}: ${v}`;
    protoStrip.appendChild(span);
  });

  // Locked files notice
  if (res.lockedFiles && res.lockedFiles.length > 0) {
    $('locked-alert-bar').hidden = false;
    $('locked-summary-text').textContent = `${res.lockedFiles.length} فایل قفل‌دار رمز عبور دارد و نیاز به تست رمز جدید دارد.`;
  } else {
    $('locked-alert-bar').hidden = true;
  }

  // Failed sources
  if (res.failedSources && res.failedSources.length > 0) {
    $('failed-list-box').hidden = false;
    const ul = $('failed-list');
    ul.innerHTML = '';
    res.failedSources.forEach((f) => {
      const li = document.createElement('li');
      li.className = 'locked-modal-row';
      li.textContent = `${f.fileName} — ${f.error}`;
      ul.appendChild(li);
    });
  } else {
    $('failed-list-box').hidden = true;
  }

  // Previews
  $('pre-xray').textContent = res.previewXray || 'موردی یافت نشد.';
  $('pre-b64').textContent = res.previewXrayBase64 || 'موردی یافت نشد.';
  $('pre-sb').textContent = res.previewSingbox || 'کانفیگ سازگار با Sing-box یافت نشد.';
  $('pre-mh').textContent = res.previewMihomo || 'کانفیگ سازگار با Mihomo یافت نشد.';

  const compEntries = Object.entries(res.previewCompanions || {});
  $('pre-comp').textContent =
    compEntries.length > 0
      ? compEntries.map(([title, body]) => `===== ${title} =====\n${body}`).join('\n\n')
      : 'فایل کمکی (SSH / DNS / OpenVPN) در این اجرا وجود نداشت.';

  const filesUl = $('written-files-list');
  filesUl.innerHTML = '';
  if (res.writtenFiles.length === 0) {
    const li = document.createElement('li');
    li.className = 'muted-text';
    li.textContent = 'مطابق تنظیمات فعلی هیچ فایلی روی دیسک نوشته نشد (احتمالاً همه گزینه‌های خروجی غیرفعال هستند).';
    filesUl.appendChild(li);
  } else {
    res.writtenFiles.forEach((wf) => {
      const li = document.createElement('li');
      li.className = 'written-file-row';
      const pSpan = document.createElement('span');
      pSpan.className = 'ltr-input';
      pSpan.textContent = wf.relPath;
      const meta = document.createElement('span');
      meta.className = 'muted-text ltr-inline';
      meta.textContent = `${wf.format} • ${formatBytes(wf.sizeBytes)}`;
      li.append(pSpan, meta);
      filesUl.appendChild(li);
    });
  }

  $('results-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function openLockedModal(lockedFiles) {
  const list = $('locked-files-modal-list');
  list.innerHTML = '';
  lockedFiles.forEach((lf) => {
    const li = document.createElement('li');
    li.className = 'locked-modal-row';
    li.textContent = `${lf.fileName}${lf.displayMessage ? ' — ' + lf.displayMessage : ''}`;
    list.appendChild(li);
  });
  $('input-retry-password').value = '';
  $('dialog-locked').showModal();
}

// ---------------- EXECUTION ----------------
async function runDecryptBatch() {
  clearAlert();
  const subsText = $('textarea-subs').value;
  const messyText = $('textarea-messy').value;
  if (appState.queuedSources.length === 0 && !subsText.trim() && !messyText.trim()) {
    showAlert('هیچ فایل، لینک اشتراک یا متن ورودی در صف وجود ندارد. ابتدا فایل‌ها یا پوشه را انتخاب کنید.');
    return;
  }

  const opts = collectOptions();
  if (!opts.outputScope.mixAll && !opts.outputScope.perSource) {
    showAlert('حداقل یکی از گزینه‌های «پوشه میکس کلی» یا «پوشه مجزا برای هر منبع» را فعال کنید.');
    return;
  }

  const batchPwRaw = $('input-batch-pass').value.trim();
  const batchPasswords = batchPwRaw ? [batchPwRaw] : [];

  $('btn-run-process').disabled = true;
  $('progress-box').hidden = false;
  $('progress-bar').value = 5;
  $('progress-percent-label').textContent = '5%';
  $('progress-item-label').textContent = 'در حال شروع پردازش...';

  try {
    const result = await invoke('run_decrypt_batch', {
      req: {
        sources: appState.queuedSources,
        subscriptionUrlsText: subsText,
        messyText,
        batchPasswords,
        options: opts,
        trackedFolderPath: appState.trackedFolderPath,
        trackedIncludeSubfolders: appState.trackedIncludeSubfolders,
      },
    });
    renderBatchResult(result);
    if (result.lockedFiles && result.lockedFiles.length > 0) {
      openLockedModal(result.lockedFiles);
    }
  } catch (err) {
    showAlert(String(err));
  } finally {
    $('btn-run-process').disabled = false;
  }
}

async function retryLockedWithPassword() {
  const res = appState.lastResult;
  if (!res || !res.lockedFiles || res.lockedFiles.length === 0) return;
  const password = $('input-retry-password').value.trim();
  if (!password) return;

  const saveToVault = $('chk-save-retry-pass').checked;
  const opts = collectOptions();
  $('btn-submit-retry-password').disabled = true;

  try {
    const retryRes = await invoke('retry_locked_with_password', {
      req: {
        lockedFiles: res.lockedFiles,
        password,
        saveToVault,
        options: opts,
        trackedFolderPath: appState.trackedFolderPath,
        trackedIncludeSubfolders: appState.trackedIncludeSubfolders,
      },
    });
    if (saveToVault && !appState.passwords.includes(password)) {
      appState.passwords.push(password);
      renderVaultList();
    }
    $('dialog-locked').close();
    if (retryRes.succeededSources > 0 && res.lockedFiles.length < res.totalSources) {
      // Re-run full batch with the discovered password so Mix_All & totals include both earlier and newly unlocked configs
      if (!$('input-batch-pass').value.trim()) {
        $('input-batch-pass').value = password;
      }
      await runDecryptBatch();
    } else {
      renderBatchResult(retryRes);
    }
  } catch (err) {
    showAlert(String(err));
  } finally {
    $('btn-submit-retry-password').disabled = false;
  }
}

async function refreshProxyStatus() {
  if (!invoke) return;
  const dot = $('proxy-dot');
  const lbl = $('proxy-status-label');
  try {
    const p = await invoke('detect_proxy_status');
    if (p) {
      dot.className = 'status-dot online';
      lbl.textContent = `VPN / پروکسی فعال: ${p.replace('http://', '')}`;
    } else {
      dot.className = 'status-dot warn';
      lbl.textContent = 'پروکسی لوکال یافت نشد (اتصال مستقیم)';
    }
  } catch (_) {
    dot.className = 'status-dot';
    lbl.textContent = 'عدم امکان بررسی پروکسی';
  }
}

// ---------------- DRAG & DROP ----------------
function initDragDrop() {
  // Prevent browser navigating away on file drop
  ['dragover', 'drop'].forEach((evt) => {
    document.addEventListener(evt, (e) => e.preventDefault());
  });

  const dz = $('drop-zone');
  dz.addEventListener('dragenter', () => dz.classList.add('drag-active'));
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-active'));
  dz.addEventListener('drop', async (e) => {
    dz.classList.remove('drag-active');
    if (!invoke && e.dataTransfer?.files?.length) {
      // Non-Tauri fallback reading
      const loaded = [];
      for (const f of e.dataTransfer.files) {
        const text = await f.text();
        loaded.push({
          id: `web-${f.name}-${f.size}`,
          name: f.name,
          path: null,
          size: f.size,
          kind: 'file',
          rawContent: text,
        });
      }
      addSourcesToQueue(loaded);
    }
  });

  if (listen) {
    listen('tauri://drag-enter', () => {
      dz.classList.add('drag-active');
    });
    listen('tauri://drag-leave', () => {
      dz.classList.remove('drag-active');
    });
    listen('tauri://drag-drop', async (event) => {
      dz.classList.remove('drag-active');
      const paths = event?.payload?.paths || [];
      if (!paths.length) return;
      try {
        const inspect = await invoke('inspect_dropped_paths', {
          paths,
          includeSubfolders: $('chk-subfolders').checked,
        });
        addSourcesToQueue(inspect.accepted);
        if (inspect.unsupportedNames.length > 0) {
          showAlert(
            `فایل‌های غیرپشتیبانی‌شده نادیده گرفته شدند: ${inspect.unsupportedNames.join('، ')}`
          );
        }
        // Automatically switch to Files tab if user dropped files while on another tab
        $('tab-files').click();
      } catch (err) {
        showAlert(String(err));
      }
    });
  }
}

// ---------------- BOOTSTRAP ----------------
async function bootstrap() {
  initTabs();
  document.querySelectorAll('dialog.m3-dialog').forEach(setupDialogCloseCleanup);
  initDragDrop();

  document.querySelectorAll('.seg-btn[data-theme]').forEach((btn) => {
    btn.addEventListener('click', () => {
      applyTheme(btn.dataset.theme);
      persistCurrentSettings();
    });
  });

  $('btn-proxy-status').addEventListener('click', refreshProxyStatus);
  $('btn-open-vault').addEventListener('click', () => {
    renderVaultList();
    $('dialog-vault').showModal();
  });

  $('btn-add-vault-pass').addEventListener('click', () => {
    const raw = $('input-new-vault-pass').value;
    const lines = raw
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    for (const pw of lines) {
      if (!appState.passwords.includes(pw)) appState.passwords.push(pw);
    }
    $('input-new-vault-pass').value = '';
    renderVaultList();
    persistCurrentSettings();
  });

  $('btn-pick-folder').addEventListener('click', async () => {
    if (!invoke) return;
    const chosen = await invoke('pick_folder', { title: 'انتخاب پوشه فایل‌های کانفیگ' });
    if (chosen) {
      $('input-folder-path').value = chosen;
      persistCurrentSettings();
    }
  });

  $('btn-pick-output-dir').addEventListener('click', async () => {
    if (!invoke) return;
    const chosen = await invoke('pick_folder', { title: 'انتخاب پوشه مقصد خروجی‌ها' });
    if (chosen) {
      $('input-output-dir').value = chosen;
      persistCurrentSettings();
    }
  });

  $('btn-pick-files').addEventListener('click', async () => {
    if (!invoke) return;
    const files = await invoke('pick_files');
    if (files && files.length) {
      addSourcesToQueue(files);
    }
  });
  $('drop-zone').addEventListener('click', (e) => {
    if (e.target.id !== 'btn-pick-files') $('btn-pick-files').click();
  });
  $('drop-zone').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      $('btn-pick-files').click();
    }
  });

  $('btn-scan-all').addEventListener('click', () => performFolderScan(false));
  $('btn-scan-new').addEventListener('click', () => performFolderScan(true));

  $('btn-reset-folder-history').addEventListener('click', async () => {
    const fp = $('input-folder-path').value.trim();
    if (!fp || !invoke) return;
    const ok = await askConfirm(
      'آیا مطمئن هستید که سابقه فایل‌های واردشده برای این پوشه پاک شود؟ با این کار دفعه بعد همه فایل‌ها به‌عنوان جدید شناخته می‌شوند.'
    );
    if (ok) {
      await invoke('clear_folder_history', { folderPath: fp });
      $('folder-scan-report').hidden = false;
      $('folder-scan-report').textContent = 'سابقه اسکن این پوشه پاک شد.';
    }
  });

  $('btn-clear-queue').addEventListener('click', () => {
    appState.queuedSources = [];
    renderQueue();
  });

  $('select-proxy-mode').addEventListener('change', () => {
    $('custom-proxy-wrap').hidden = $('select-proxy-mode').value !== 'custom';
    persistCurrentSettings();
  });

  $('btn-proto-all').addEventListener('click', () => {
    appState.selectedProtocols = new Set(appState.allProtocols);
    renderProtocolChips();
    persistCurrentSettings();
  });

  $('btn-proto-none').addEventListener('click', () => {
    appState.selectedProtocols.clear();
    renderProtocolChips();
    persistCurrentSettings();
  });

  [
    'chk-subfolders',
    'chk-move-trash',
    'chk-filter-dups',
    'chk-filter-broken',
    'chk-ignore-expired',
    'chk-limit-max',
    'input-max-configs',
    'input-output-dir',
    'chk-scope-mix',
    'chk-scope-persrc',
    'chk-fmt-xray',
    'chk-fmt-xray-b64',
    'chk-fmt-singbox',
    'chk-fmt-mihomo',
    'chk-fmt-companions',
    'chk-split-all',
    'chk-split-byproto',
    'input-custom-proxy',
  ].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener('change', persistCurrentSettings);
  });

  $('btn-run-process').addEventListener('click', runDecryptBatch);
  $('btn-open-locked-modal').addEventListener('click', () => {
    if (appState.lastResult?.lockedFiles) openLockedModal(appState.lastResult.lockedFiles);
  });
  $('btn-submit-retry-password').addEventListener('click', retryLockedWithPassword);

  $('btn-open-output').addEventListener('click', () => {
    const outDir = appState.lastResult?.outputDir || $('input-output-dir').value.trim();
    if (outDir && invoke) {
      invoke('open_folder_in_explorer', { path: outDir }).catch((e) => showAlert(String(e)));
    }
  });

  $('btn-copy-preview').addEventListener('click', async () => {
    const map = {
      'ppanel-xray': 'pre-xray',
      'ppanel-b64': 'pre-b64',
      'ppanel-sb': 'pre-sb',
      'ppanel-mh': 'pre-mh',
      'ppanel-comp': 'pre-comp',
    };
    const preId = map[appState.activePreviewTab];
    if (!preId) return;
    const text = $(preId).textContent || '';
    try {
      await navigator.clipboard.writeText(text);
      const btn = $('btn-copy-preview');
      const old = btn.textContent;
      btn.textContent = 'کپی شد ✓';
      setTimeout(() => {
        btn.textContent = old;
      }, 1600);
    } catch (_) {}
  });

  if (listen) {
    listen('decrypt-progress', (ev) => {
      const p = ev.payload;
      if (!p) return;
      $('progress-bar').value = p.percent;
      $('progress-percent-label').textContent = `${p.percent}%`;
      $('progress-item-label').textContent = `${p.current} / ${p.total} — ${p.currentItem}`;
    });
  }

  if (invoke) {
    try {
      const init = await invoke('get_initial_state');
      appState.allProtocols = init.allProtocols;
      appState.passwords = init.state.passwords || [];
      const savedProtos = init.state.options?.allowedProtocols;
      appState.selectedProtocols = new Set(
        savedProtos && savedProtos.length ? savedProtos : init.allProtocols
      );
      applyOptionsToUI(init.state.options);
      if (!$('input-output-dir').value.trim() && init.defaultOutputDir) {
        $('input-output-dir').value = init.defaultOutputDir;
      }
      if (init.state.lastFolderPath) {
        $('input-folder-path').value = init.state.lastFolderPath;
      }
      $('chk-subfolders').checked = Boolean(init.state.includeSubfolders);

      const theme = init.state.theme || 'system';
      applyTheme(theme);

      renderProtocolChips();
      renderVaultList();

      if (init.detectedProxy) {
        $('proxy-dot').className = 'status-dot online';
        $('proxy-status-label').textContent = `VPN / پروکسی فعال: ${init.detectedProxy.replace(
          'http://',
          ''
        )}`;
      } else {
        $('proxy-dot').className = 'status-dot warn';
        $('proxy-status-label').textContent = 'پروکسی لوکال یافت نشد (اتصال مستقیم)';
      }
    } catch (err) {
      showAlert(`خطا در بارگذاری تنظیمات اولیه: ${err}`);
    }
  }
}

bootstrap();
