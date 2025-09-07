use std::path::PathBuf;
use win64_emulator::emulation::Emulator;

#[test]
fn test_enigma_protected() {
    let test_exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("enigma_test_protected.exe");
    
    let result = Emulator::new(test_exe.to_str().unwrap());
    assert!(result.is_ok(), "Failed to load enigma protected exe");
    
    let mut emulator = result.unwrap();
    
    let run_result = emulator.run(635_314_000);
    
    match run_result {
        Ok(_) => println!("Enigma protected exe ran successfully"),
        Err(e) => println!("Enigma protected exe failed: {:?}", e),
    }
}

/*#[test]
fn test_enigma_unprotected() {
    let test_exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("enigma_test_unprotected.exe");
    
    let result = Emulator::new(test_exe.to_str().unwrap());
    assert!(result.is_ok(), "Failed to load enigma unprotected exe");
    
    let mut emulator = result.unwrap();
    
    let run_result = emulator.run(0);
    assert!(run_result.is_ok(), "Failed to run enigma unprotected exe");
}*/
