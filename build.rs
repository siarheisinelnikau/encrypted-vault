fn main() {
    println!("cargo:rerun-if-changed=assets/app.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set("ProductName", "Encrypted Vault")
            .set("FileDescription", "Encrypted Vault")
            .set("LegalCopyright", "Copyright (c) 2026 Encrypted Vault contributors")
            .set_manifest(r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity version="0.1.0.0" processorArchitecture="*" name="EncryptedVault" type="win32"/><trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo><application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings><dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness><longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware></windowsSettings></application></assembly>"#);
        if std::path::Path::new("assets/app.ico").exists() {
            res.set_icon("assets/app.ico");
        }
        res.compile()
            .expect("compile Windows icon and version resources");
    }
}
