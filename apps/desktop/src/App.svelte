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
    <div class="vault-status">
      <i></i><span><b>Vault not created</b><small>Local storage · locked</small></span>
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
        <div class="hero-card"><p class="eyebrow">YOUR LOCAL VAULT</p><h2>Credential vault</h2><p class="muted">Your encrypted credential collection will be managed here. Vault creation, unlock, and credential operations are not connected yet.</p></div>
        <div class="empty-state"><span class="feature-icon">▤</span><h3>Vault engine in development</h3><p class="muted">The versioned encrypted container and secure session lifecycle are being implemented before credential storage is enabled.</p></div>
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
