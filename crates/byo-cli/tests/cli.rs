use std::error::Error;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use byo_core::MAX_ENCODED_IMAGE_BYTES;

fn temporary_directory() -> Result<std::path::PathBuf, Box<dyn Error>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let directory =
        std::env::temp_dir().join(format!("byo-cli-test-{}-{timestamp}", std::process::id()));
    fs::create_dir(&directory)?;
    Ok(directory)
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/qr")
        .join(name)
}

fn run_qr(path: &Path, json: bool) -> Result<Output, Box<dyn Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_byo"));
    if json {
        command.arg("--json");
    }
    Ok(command.arg("qr").arg(path).output()?)
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

#[test]
fn qr_text_and_nested_url_analysis_work_end_to_end() -> Result<(), Box<dyn Error>> {
    let text = run_qr(&fixture("text.png"), false)?;
    assert!(text.status.success());
    let text_stdout = String::from_utf8(text.stdout)?;
    assert!(text_stdout.contains("Payload: Hello from BYO"));
    assert!(text_stdout.contains("Network activity: none"));

    let url = run_qr(&fixture("tracking.png"), true)?;
    assert!(url.status.success());
    let url_stdout = String::from_utf8(url.stdout)?;
    let _: serde_json::Value = serde_json::from_str(&url_stdout)?;
    assert!(url_stdout.contains("\"kind\": \"url\""));
    assert!(url_stdout.contains("url.tracking_parameter"));
    assert!(url_stdout.contains("\"network_activity\": false"));
    Ok(())
}

#[test]
fn qr_url_and_wifi_secrets_are_absent_from_human_and_json() -> Result<(), Box<dyn Error>> {
    for (filename, secret) in [
        ("credentials.png", "BYO_SECRET_SENTINEL"),
        ("wifi.png", "BYO_WIFI_SECRET_SENTINEL"),
    ] {
        for json in [false, true] {
            let output = run_qr(&fixture(filename), json)?;
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout)?;
            assert!(!stdout.contains(secret));
            assert!(stdout.contains("password"));
        }
    }
    Ok(())
}

#[test]
fn qr_payload_controls_never_reach_terminal_output_raw() -> Result<(), Box<dyn Error>> {
    let output = run_qr(&fixture("controls.png"), false)?;
    assert!(output.status.success());
    assert!(!output.stdout.contains(&0x1b));
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(r"line one\n\x1B[31mline two"));
    assert!(!stdout.contains("line one\n\u{1b}"));
    Ok(())
}

#[test]
fn qr_active_and_punycode_urls_reuse_existing_findings() -> Result<(), Box<dyn Error>> {
    let active = run_qr(&fixture("active-scheme.png"), true)?;
    assert!(active.status.success());
    let active_stdout = String::from_utf8(active.stdout)?;
    assert!(active_stdout.contains("url.active_content_scheme"));

    let punycode = run_qr(&fixture("punycode.png"), true)?;
    assert!(punycode.status.success());
    let punycode_stdout = String::from_utf8(punycode.stdout)?;
    assert!(punycode_stdout.contains("url.punycode_hostname"));
    assert!(punycode_stdout.contains("bücher.example"));
    Ok(())
}

#[test]
fn oversized_qr_source_is_refused_from_metadata() -> Result<(), Box<dyn Error>> {
    let directory = temporary_directory()?;
    let path = directory.join("oversized.png");
    let file = File::create(&path)?;
    file.set_len(MAX_ENCODED_IMAGE_BYTES.saturating_add(1))?;
    drop(file);

    let output = run_qr(&path, false)?;
    fs::remove_dir_all(&directory)?;

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("qr.image.encoded_size_limit"));
    assert!(stdout.contains("refused before reading"));
    Ok(())
}

#[test]
fn qr_command_rejects_a_directory() -> Result<(), Box<dyn Error>> {
    let directory = temporary_directory()?;
    let output = run_qr(&directory, false)?;
    fs::remove_dir(&directory)?;

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("qr.path.directory_rejected"));
    Ok(())
}

#[test]
fn malformed_and_zero_qr_images_have_explicit_states() -> Result<(), Box<dyn Error>> {
    for filename in ["truncated.png", "truncated.jpg"] {
        let malformed = run_qr(&fixture(filename), false)?;
        assert!(!malformed.status.success());
        let stdout = String::from_utf8(malformed.stdout)?;
        assert!(stdout.contains("State: Failed"));
    }

    let corrupt = run_qr(&fixture("corrupt-qr.png"), false)?;
    assert!(corrupt.status.success());
    let corrupt_stdout = String::from_utf8(corrupt.stdout)?;
    assert!(corrupt_stdout.contains("qr.code_decode_failed"));
    assert!(corrupt_stdout.contains("State: Partial"));

    let zero = run_qr(&fixture("no-code.png"), false)?;
    assert!(zero.status.success());
    let zero_stdout = String::from_utf8(zero.stdout)?;
    assert!(zero_stdout.contains("No QR code was detected"));
    assert!(zero_stdout.contains("State: Complete"));
    Ok(())
}
