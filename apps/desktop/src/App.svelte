<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  type Page = "overview" | "passwords" | "generator" | "backups" | "settings";
  let page: Page = "overview";
  let dark = false;
  let generatorLength = 24;
  let includeLowercase = true;
  let includeUppercase = true;
  let includeDigits = true;
  let includeSymbols = true;
  let generatedPassword = "";
  let generatorMessage = "";
  let generatorBusy = false;
  let vaultExists = false;
  let vaultUnlocked = false;
  let vaultLoading = true;
  let vaultBusy = false;
  let vaultMessage = "";
  let vaultMessageError = false;
  let masterPassword = "";
  let confirmMasterPassword = "";
  let newMasterPassword = "";
  let confirmNewMasterPassword = "";

  const navigation: { id: Page; icon: string; label: string }[] = [
    { id: "overview", icon: "◫", label: "Overview" },
    { id: "passwords", icon: "▤", label: "Passwords" },
    { id: "generator", icon: "✳", label: "Generator" },
    { id: "backups", icon: "◷", label: "Backups" },
  ];

  $: hasCharacterClass = includeLowercase || includeUppercase || includeDigits || includeSymbols;

  function applyTheme(value: boolean): void {
    dark = value;
    document.body.classList.toggle("dark", value);
    document.documentElement.style.colorScheme = value ? "dark" : "light";
    localStorage.setItem("nexus-q-password-theme", value ? "dark" : "light");
  }

  function navigate(next: Page): void {
    if (next !== "generator") {
      generatedPassword = "";
      generatorMessage = "";
    }
    page = next;
  }

  async function generatePassword(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    generatorBusy = true;
    generatorMessage = "";
    generatedPassword = "";
    try {
      generatedPassword = await invoke<string>("generate_password", {
        length: Number(generatorLength),
        lowercase: includeLowercase,
        uppercase: includeUppercase,
        digits: includeDigits,
        symbols: includeSymbols,
      });
    } catch {
      generatorMessage = "The password could not be generated. Check the selected options and try again.";
    } finally {
      generatorBusy = false;
    }
  }

  async function refreshVaultStatus(): Promise<void> {
    vaultLoading = true;
    try {
      vaultExists = await invoke<boolean>("vault_exists");
      vaultUnlocked = await invoke<boolean>("vault_is_unlocked");
    } catch {
      vaultMessage = "The vault status could not be read. Restart the application and try again.";
      vaultMessageError = true;
    } finally {
      vaultLoading = false;
    }
  }

  async function createVault(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    vaultMessage = "";
    vaultMessageError = false;
    if (masterPassword.length < 12) {
      vaultMessage = "Use a master password with at least 12 characters.";
      vaultMessageError = true;
      return;
    }
    if (masterPassword !== confirmMasterPassword) {
      vaultMessage = "The master passwords do not match.";
      vaultMessageError = true;
      return;
    }
    vaultBusy = true;
    try {
      await invoke("vault_create", { masterPassword });
      masterPassword = "";
      confirmMasterPassword = "";
      await refreshVaultStatus();
      vaultMessage = "Your encrypted vault has been created and is unlocked on this device.";
    } catch {
      vaultMessage = "The vault could not be created. Check available storage and try again.";
      vaultMessageError = true;
    } finally {
      masterPassword = "";
      confirmMasterPassword = "";
      vaultBusy = false;
    }
  }

  async function unlockVault(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    vaultBusy = true;
    vaultMessage = "";
    vaultMessageError = false;
    try {
      await invoke("vault_unlock", { masterPassword });
      await refreshVaultStatus();
      vaultMessage = "Vault unlocked. The derived encryption key is held in protected memory for this session.";
    } catch {
      vaultMessage = "Unable to unlock the vault. Check the master password and try again.";
      vaultMessageError = true;
    } finally {
      masterPassword = "";
      vaultBusy = false;
    }
  }

  async function lockVault(): Promise<void> {
    vaultBusy = true;
    vaultMessage = "";
    vaultMessageError = false;
    try {
      await invoke("vault_lock");
      await refreshVaultStatus();
      vaultMessage = "Vault locked. The active encryption key has been discarded.";
    } catch {
      vaultMessage = "The vault could not be locked. Please try again.";
      vaultMessageError = true;
    } finally {
      vaultBusy = false;
    }
  }

  async function changeMasterPassword(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    vaultMessage = "";
    vaultMessageError = false;
    if (newMasterPassword.length < 12) {
      vaultMessage = "Use a new master password with at least 12 characters.";
      vaultMessageError = true;
      return;
    }
    if (newMasterPassword !== confirmNewMasterPassword) {
      vaultMessage = "The new master passwords do not match.";
      vaultMessageError = true;
      return;
    }
    vaultBusy = true;
    try {
      await invoke("vault_change_master_password", { newMasterPassword });
      vaultMessage = "Master password changed successfully.";
    } catch {
      vaultMessage = "The master password could not be changed. The previous password remains active.";
      vaultMessageError = true;
    } finally {
      newMasterPassword = "";
      confirmNewMasterPassword = "";
      vaultBusy = false;
    }
  }

  async function copyGeneratedPassword(): Promise<void> {
    if (!generatedPassword) return;
    try {
      await navigator.clipboard.writeText(generatedPassword);
      generatorMessage = "Copied to clipboard. Clear it manually when you are finished.";
    } catch {
      generatorMessage = "Clipboard access is unavailable. Select and copy the password manually.";
    }
  }

  onMount(() => {
    applyTheme(localStorage.getItem("nexus-q-password-theme") === "dark");
    void refreshVaultStatus();
  });
</script>

<svelte:head>
  <title>NEXUS-Q Password</title>
</svelte:head>

<div class="app-layout">
  <aside class="sidebar">
    <a class="side-brand" href="#overview" onclick={() => navigate("overview")}>
      <img src="/assets/nexus-q-mark.png" alt="NEXUS-Q" />
      <span><b>NEXUS-Q <strong>Password</strong></b><small>LOCAL CREDENTIAL VAULT</small></span>
    </a>

    <div class="side-label">WORKSPACE</div>
    <nav class="side-nav" aria-label="Main navigation">
      {#each navigation as item}
        <button class:active={page === item.id} class="nav-item" onclick={() => navigate(item.id)} aria-current={page === item.id ? "page" : undefined}>
          <span class="nav-icon">{item.icon}</span><span class="nav-label">{item.label}</span>
        </button>
      {/each}
    </nav>

    <div class="sidebar-spacer"></div>
    <nav class="side-nav settings-nav" aria-label="Settings">
      <button class:active={page === "settings"} class="nav-item" onclick={() => navigate("settings")}>
        <span class="nav-icon">⚙</span><span class="nav-label">Settings</span>
      </button>
    </nav>
    <div class="vault-status" class:unlocked={vaultUnlocked}>
      <i></i><span><b>{vaultUnlocked ? "Vault unlocked" : vaultExists ? "Vault locked" : "Vault not created"}</b><small>Local storage · {vaultUnlocked ? "session active" : "locked"}</small></span>
    </div>
    <div class="version">VERSION 0.1.0 · DEVELOPMENT</div>
  </aside>

  <main class="main-area">
    <header class="topbar">
      <div>
        <p class="eyebrow">NEXUS-Q / PASSWORD</p>
        <h1>{navigation.find((item) => item.id === page)?.label ?? "Settings"}</h1>
      </div>
      <div class="top-actions">
        <span class="status-pill">LOCAL-FIRST · OFFLINE</span>
        <button class="icon-button" onclick={() => applyTheme(!dark)} aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}>{dark ? "☼" : "◐"}</button>
      </div>
    </header>

    {#if page === "overview"}
      <section class="content">
        <div class="hero-card overview-hero">
          <p class="eyebrow">PRIVATE BY DESIGN</p>
          <h2>Your credentials.<br /><span>Under your control.</span></h2>
          <p class="muted">A local password vault designed around privacy, authenticated encryption, and control that stays on your device.</p>
          <div class="meta-row"><span><b>01</b> Local encrypted vault</span><span><b>02</b> Master-password protection</span><span><b>03</b> No cloud account</span></div>
        </div>
        <div class="action-grid">
          <button class="action-card" onclick={() => navigate("passwords")}>
            <span class="feature-icon">▤</span><h3>Credential vault</h3><p>Store, organize, search, and manage your credentials in an encrypted local vault.</p>
          </button>
          <button class="action-card" onclick={() => navigate("generator")}>
            <span class="feature-icon">✳</span><h3>Password generator</h3><p>Create strong, cryptographically random passwords with configurable rules.</p>
          </button>
        </div>
        <div class="notice"><b>Development build</b><p>The security architecture and application shell are being established. Do not store real credentials in this development version.</p></div>
      </section>
    {:else if page === "passwords"}
      <section class="content">
        <div class="hero-card"><p class="eyebrow">YOUR LOCAL VAULT</p><h2>Credential vault</h2><p class="muted">Create or unlock your encrypted local vault. Credential storage remains disabled until its encrypted record layer is complete.</p></div>
        {#if vaultLoading}
          <div class="empty-state"><h3>Checking vault status…</h3><p class="muted">Reading the local vault state securely.</p></div>
        {:else if vaultUnlocked}
          <div class="vault-panel">
            <div class="vault-panel-heading"><span class="feature-icon">◈</span><div><h3>Vault is unlocked</h3><p class="muted">Your session is active. The master password is not retained.</p></div></div>
            <div class="session-details"><span>ENCRYPTED CONTAINER</span><b>NQPW · Version 1</b><span>SESSION KEY</span><b>Protected in memory</b><span>CREDENTIAL RECORDS</span><b>Not enabled in this build</b></div>
            <button class="secondary-action" type="button" onclick={lockVault} disabled={vaultBusy}>Lock vault</button>
          </div>
          <div class="vault-panel password-change-panel">
            <p class="eyebrow">ACCOUNT SECURITY</p><h3>Change master password</h3><p class="muted">The new encrypted container is saved before the active session key is rotated.</p>
            <form class="vault-form" onsubmit={changeMasterPassword}>
              <label for="new-master-password">New master password</label><input id="new-master-password" type="password" bind:value={newMasterPassword} minlength="12" maxlength="1024" autocomplete="new-password" required />
              <label for="confirm-new-master-password">Confirm new master password</label><input id="confirm-new-master-password" type="password" bind:value={confirmNewMasterPassword} minlength="12" maxlength="1024" autocomplete="new-password" required />
              <button class="primary-action" type="submit" disabled={vaultBusy}>Change master password</button>
            </form>
          </div>
        {:else if vaultExists}
          <div class="vault-panel">
            <div class="vault-panel-heading"><span class="feature-icon">▣</span><div><h3>Unlock your vault</h3><p class="muted">Enter your master password to authenticate and open the local encrypted container.</p></div></div>
            <form class="vault-form" onsubmit={unlockVault}>
              <label for="master-password">Master password</label><input id="master-password" type="password" bind:value={masterPassword} maxlength="1024" autocomplete="current-password" required />
              <button class="primary-action" type="submit" disabled={vaultBusy || !masterPassword}>{vaultBusy ? "Unlocking…" : "Unlock vault"}</button>
            </form>
          </div>
        {:else}
          <div class="vault-panel">
            <div class="vault-panel-heading"><span class="feature-icon">＋</span><div><h3>Create your encrypted vault</h3><p class="muted">Choose a strong master password. It cannot be recovered if you forget it.</p></div></div>
            <form class="vault-form" onsubmit={createVault}>
              <label for="create-master-password">Master password</label><input id="create-master-password" type="password" bind:value={masterPassword} minlength="12" maxlength="1024" autocomplete="new-password" required />
              <label for="confirm-master-password">Confirm master password</label><input id="confirm-master-password" type="password" bind:value={confirmMasterPassword} minlength="12" maxlength="1024" autocomplete="new-password" required />
              <p class="form-hint">Use at least 12 characters. A longer unique passphrase is recommended.</p>
              <button class="primary-action" type="submit" disabled={vaultBusy || !masterPassword || !confirmMasterPassword}>{vaultBusy ? "Creating vault…" : "Create encrypted vault"}</button>
            </form>
          </div>
        {/if}
        {#if vaultMessage}<p class="vault-message" class:error={vaultMessageError} aria-live="polite">{vaultMessage}</p>{/if}
        <div class="notice"><b>Credential storage is not enabled</b><p>This build currently verifies vault creation, authentication, and session locking only. Do not treat it as ready for real credentials.</p></div>
      </section>
    {:else if page === "generator"}
      <section class="content">
        <div class="hero-card"><p class="eyebrow">CRYPTOGRAPHIC RANDOMNESS</p><h2>Password generator</h2><p class="muted">Generate strong passwords using the operating system's cryptographically secure random source. Character selection avoids modulo bias and guarantees every selected class appears at least once.</p></div>
        <div class="generator-card">
          <form onsubmit={generatePassword}>
            <label for="generator-length">Password length</label>
            <div class="length-control"><input id="generator-length" type="number" min="8" max="128" bind:value={generatorLength} /><span>8–128 characters</span></div>
            <fieldset class="generator-options">
              <legend>Include character types</legend>
              <label><input type="checkbox" bind:checked={includeLowercase} /> Lowercase letters (a–z)</label>
              <label><input type="checkbox" bind:checked={includeUppercase} /> Uppercase letters (A–Z)</label>
              <label><input type="checkbox" bind:checked={includeDigits} /> Numbers (0–9)</label>
              <label><input type="checkbox" bind:checked={includeSymbols} /> Symbols (!@#$…)</label>
            </fieldset>
            <button class="primary-action" type="submit" disabled={generatorBusy || !hasCharacterClass || generatorLength < 8 || generatorLength > 128}>{generatorBusy ? "Generating…" : "Generate password"}</button>
          </form>
          {#if generatedPassword}
            <div class="generated-result">
              <label for="generated-password">Generated password</label>
              <input id="generated-password" type="text" readonly value={generatedPassword} autocomplete="off" spellcheck="false" />
              <button class="secondary-action" type="button" onclick={copyGeneratedPassword}>Copy password</button>
            </div>
          {/if}
          {#if generatorMessage}<p class="generator-message" aria-live="polite">{generatorMessage}</p>{/if}
          <p class="settings-note">Generated passwords are held temporarily in the application interface. Leaving this screen clears the displayed value. Clipboard contents are not automatically cleared yet.</p>
        </div>
      </section>
    {:else if page === "backups"}
      <section class="content">
        <div class="hero-card"><p class="eyebrow">RECOVERY & PORTABILITY</p><h2>Encrypted backups</h2><p class="muted">Backups will use an independent password, salt, key derivation parameters, and authenticated encryption.</p></div>
        <div class="empty-state"><span class="feature-icon">◷</span><h3>Backup system in development</h3><p class="muted">Backup and restore will be enabled only after format and recovery tests pass.</p></div>
      </section>
    {:else}
      <section class="content">
        <div class="hero-card"><p class="eyebrow">PREFERENCES</p><h2>Settings</h2><p class="muted">Application preferences and security controls will be available here.</p></div>
        <div class="setting-line"><div><b>Appearance</b><p class="muted">Choose the application theme.</p></div><button class="secondary-action" onclick={() => applyTheme(!dark)}>{dark ? "Dark" : "Light"}</button></div>
        <div class="setting-line"><div><b>Automatic lock</b><p class="muted">Lock the vault after a period of inactivity.</p></div><span class="muted">Not configured</span></div>
        <p class="settings-version">NEXUS-Q Password · 0.1.0 · Independent local-first application</p>
      </section>
    {/if}
  </main>
</div>
