use std::error::Error;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_directory() -> Result<std::path::PathBuf, Box<dyn Error>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let directory =
        std::env::temp_dir().join(format!("byo-cli-test-{}-{timestamp}", std::process::id()));
    fs::create_dir(&directory)?;
    Ok(directory)
}

#[test]
fn file_command_inspects_safe_synthetic_data_end_to_end() -> Result<(), Box<dyn Error>> {
    let directory = temporary_directory()?;
    let path = directory.join("synthetic.png");
    fs::write(&path, b"\x89PNG\r\n\x1a\nsmall public test payload")?;

    let output = Command::new(env!("CARGO_BIN_EXE_byo"))
        .arg("file")
        .arg(&path)
        .output()?;
    let cleanup_result = fs::remove_dir_all(&directory);
    cleanup_result?;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("file.signature.png"));
    assert!(stdout.contains("file.sha256"));
    assert!(stdout.contains("Network activity: none"));
    Ok(())
}

#[test]
fn url_command_is_offline_structured_and_redacted_end_to_end() -> Result<(), Box<dyn Error>> {
    let secret = "end-to-end-secret";
    let input = format!("https://user:{secret}@xn--bcher-kva.example/path?utm_source=test&item=1");
    let output = Command::new(env!("CARGO_BIN_EXE_byo"))
        .args(["--json", "url", &input])
        .output()?;

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("url.punycode_hostname"));
    assert!(stdout.contains("url.tracking_parameter"));
    assert!(stdout.contains("\"network_activity\": false"));
    assert!(!stdout.contains(secret));
    Ok(())
}
