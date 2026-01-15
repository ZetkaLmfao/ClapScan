fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        
        // Try to set icon but don't fail build if it doesn't work
        if std::path::Path::new("src/logo.ico").exists() {
            res.set_icon("src/logo.ico");
        }
        
        // Ignore icon errors - GUI will still have icon via runtime loading
        let _ = res.compile();
    }
}
