#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![generate_password])
        .run(tauri::generate_context!())
        .expect("error while running NEXUS-Q Password");
}
