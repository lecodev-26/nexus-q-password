#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

#[derive(Default)]
struct VaultState {
    session: Mutex<Option<nexus_q_password_core::VaultSession>>,
}

fn vault_file_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    Ok(directory.join("vault.nqpw"))
}

#[tauri::command]
fn generate_password(
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
) -> Result<String, String> {
    let generated =
        nexus_q_password_core::generate_password(nexus_q_password_core::PasswordPolicy {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
        })
        .map_err(|error| error.to_string())?;

    // The secret crosses IPC only because the user explicitly requested a generated
    // password. The frontend clears its copy when leaving the generator screen.
    Ok(generated.to_string())
}

#[tauri::command]
fn vault_create(
    app: AppHandle,
    state: State<'_, VaultState>,
    master_password: Zeroizing<String>,
) -> Result<(), String> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Vault state is unavailable.".to_string())?;
    if session.is_some() {
        return Err("Vault is already unlocked.".into());
    }
    let password = Zeroizing::new(master_password.as_bytes().to_vec());
    let (new_session, envelope) = nexus_q_password_core::VaultSession::create(&password, &[])
        .map_err(|error| error.to_string())?;
    let path = vault_file_path(&app)?;
    nexus_q_password_core::create_envelope(path, &envelope).map_err(|error| error.to_string())?;
    *session = Some(new_session);
    Ok(())
}

#[tauri::command]
fn vault_unlock(
    app: AppHandle,
    state: State<'_, VaultState>,
    master_password: Zeroizing<String>,
) -> Result<(), String> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Vault state is unavailable.".to_string())?;
    if session.is_some() {
        return Err("Vault is already unlocked.".into());
    }
    let path = vault_file_path(&app)?;
    let envelope = nexus_q_password_core::load_envelope(path).map_err(|error| error.to_string())?;
    let password = Zeroizing::new(master_password.as_bytes().to_vec());
    let (new_session, _initial_payload) =
        nexus_q_password_core::VaultSession::unlock(&password, &envelope)
            .map_err(|error| error.to_string())?;
    *session = Some(new_session);
    Ok(())
}

#[tauri::command]
fn vault_lock(state: State<'_, VaultState>) -> Result<(), String> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Vault state is unavailable.".to_string())?;
    if let Some(mut active) = session.take() {
        active.lock();
    }
    Ok(())
}

#[tauri::command]
fn vault_is_unlocked(state: State<'_, VaultState>) -> Result<bool, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "Vault state is unavailable.".to_string())?;
    Ok(session
        .as_ref()
        .is_some_and(nexus_q_password_core::VaultSession::is_unlocked))
}

#[tauri::command]
fn vault_change_master_password(
    app: AppHandle,
    state: State<'_, VaultState>,
    new_master_password: Zeroizing<String>,
) -> Result<(), String> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "Vault state is unavailable.".to_string())?;
    let active = session
        .as_mut()
        .ok_or_else(|| "Vault is locked.".to_string())?;
    let path = vault_file_path(&app)?;
    let current_envelope =
        nexus_q_password_core::load_envelope(&path).map_err(|error| error.to_string())?;
    let password = Zeroizing::new(new_master_password.as_bytes().to_vec());
    let change = active
        .prepare_master_password_change(&current_envelope, &password)
        .map_err(|error| error.to_string())?;
    nexus_q_password_core::save_envelope(&path, change.envelope())
        .map_err(|error| error.to_string())?;
    active
        .commit_master_password_change(change)
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(VaultState::default())
        .invoke_handler(tauri::generate_handler![
            generate_password,
            vault_create,
            vault_unlock,
            vault_lock,
            vault_is_unlocked,
            vault_change_master_password,
        ])
        .run(tauri::generate_context!())
        .expect("error while running NEXUS-Q Password");
}
