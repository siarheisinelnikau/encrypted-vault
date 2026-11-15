#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(windows)]
    {
        let args: Vec<_> = std::env::args_os().collect();
        let result = if args.get(1).is_some_and(|a| a == "--apply-update") {
            encrypted_vault::updates::apply_update_from_args(&args)
        } else if args.get(1).is_some_and(|a| a == "--screenshot") {
            encrypted_vault::ui::screenshot(&args)
        } else if args.len() > 1 {
            eprintln!(
                "Usage: EncryptedVault.exe [--screenshot ABSOLUTE.png home|empty|settings|create|unlock en|ru|fr|de|es|it light|dark]"
            );
            return;
        } else {
            encrypted_vault::ui::run()
        };
        if let Err(error) = result {
            // No vault passwords, keys, filenames, or file contents are included in errors.
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    eprintln!(
        "Encrypted Vault currently requires Windows 10/11 and the external Dokany 2.x runtime."
    );
}
