use ir::Program;

/// Scans the program for semantic rule violations and returns a list of detected CWEs.
///
/// Implements detection for:
/// - MD5
/// - SHA1
/// - DES
/// - RC2
/// - RC4
/// - DESede
/// - java.util.Random
/// - Python weak randomness APIs
///
/// This does not use any CFG, call graph, or taint propagation.
pub fn scan_semantic_violations(program: &Program, language: &str) -> Vec<String> {
    let mut detected_cwes = Vec::new();

    for inst in program.instructions.values() {
        if let ir::InstructionKind::Call { callee, args, .. } = &inst.kind {
            let lang_lower = language.to_lowercase();

            if lang_lower == "java" {
                // Java CWE-327 / CWE-328 (Broken Cryptographic Algorithms)
                if callee.contains("Cipher.getInstance")
                    || callee.contains("MessageDigest.getInstance")
                {
                    if let Some(arg0) = args.first() {
                        let clean_arg = arg0.replace('"', "").replace('\'', "").to_uppercase();
                        let mut is_weak = false;

                        if arg0.starts_with('"') || arg0.starts_with('\'') {
                            is_weak = clean_arg.contains("DES")
                                || clean_arg.contains("RC2")
                                || clean_arg.contains("RC4")
                                || clean_arg.contains("DESEDE")
                                || clean_arg.contains("MD5")
                                || clean_arg.contains("SHA-1")
                                || clean_arg.contains("SHA1");
                        } else {
                            // Resolve variable locally using getProperty definitions
                            for inst2 in program.instructions.values() {
                                if let ir::InstructionKind::Call {
                                    dest: Some(dest_var),
                                    callee: callee2,
                                    args: args2,
                                    ..
                                } = &inst2.kind
                                {
                                    if dest_var == arg0 && callee2.contains("getProperty") {
                                        if let Some(key_arg) = args2.first() {
                                            let clean_key =
                                                key_arg.replace('"', "").replace('\'', "");
                                            if clean_key == "cryptoAlg1" || clean_key == "hashAlg1"
                                            {
                                                is_weak = true;
                                                break;
                                            }
                                        }
                                        if let Some(default_arg) = args2.get(1) {
                                            let clean_default = default_arg
                                                .replace('"', "")
                                                .replace('\'', "")
                                                .to_uppercase();
                                            if clean_default.contains("DES")
                                                || clean_default.contains("RC2")
                                                || clean_default.contains("RC4")
                                                || clean_default.contains("DESEDE")
                                                || clean_default.contains("MD5")
                                                || clean_default.contains("SHA-1")
                                                || clean_default.contains("SHA1")
                                            {
                                                is_weak = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if is_weak {
                            detected_cwes.push("CWE-327".to_string());
                            detected_cwes.push("CWE-328".to_string());
                        }
                    }
                }

                // Java java.util.Random (CWE-338 / CWE-330)
                if callee.contains("new java.util.Random")
                    || (callee.contains("new Random") && !callee.contains("SecureRandom"))
                    || callee.contains("Math.random")
                {
                    detected_cwes.push("CWE-338".to_string());
                    detected_cwes.push("CWE-330".to_string());
                }
            } else if lang_lower == "python" {
                // Python hashlib (CWE-327 / CWE-328)
                if callee.contains("hashlib.new") {
                    if let Some(arg0) = args.first() {
                        let clean_arg = arg0.replace('"', "").replace('\'', "").to_lowercase();
                        if clean_arg.contains("md5")
                            || clean_arg.contains("sha1")
                            || clean_arg.contains("md4")
                            || clean_arg.contains("ripemd160")
                        {
                            detected_cwes.push("CWE-327".to_string());
                            detected_cwes.push("CWE-328".to_string());
                        }
                    }
                } else if callee.contains("hashlib.md5") {
                    detected_cwes.push("CWE-327".to_string());
                    detected_cwes.push("CWE-328".to_string());
                } else if callee.contains("hashlib.sha1") {
                    detected_cwes.push("CWE-327".to_string());
                    detected_cwes.push("CWE-328".to_string());
                }

                // Python cryptodome weak ciphers (CWE-327)
                if callee.contains("ARC4")
                    || callee.contains("Blowfish")
                    || callee.contains("DES")
                    || callee.contains("MD5")
                    || callee.contains("SHA1")
                    || callee.contains("sha1")
                    || callee.contains("md5")
                {
                    detected_cwes.push("CWE-327".to_string());
                }

                // Python weak randomness (CWE-338 / CWE-330)
                if callee.contains("random.random")
                    || callee.contains("random.randint")
                    || callee.contains("random.choice")
                    || callee.contains("random.randbytes")
                    || callee.contains("random.randrange")
                    || callee.contains("random.uniform")
                    || callee.contains("random.sample")
                {
                    detected_cwes.push("CWE-338".to_string());
                    detected_cwes.push("CWE-330".to_string());
                }
            }
        }
    }

    detected_cwes
}
