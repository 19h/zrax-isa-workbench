//! Raw binary analysis using heuristic scoring.
//!
//! When no recognized file format is detected, this module analyzes
//! the raw instruction stream to identify the ISA using pattern matching.

use crate::error::Result;
use crate::heuristics;
use crate::types::{ClassificationResult, ClassifierOptions};

/// Analyze raw binary data to identify the ISA.
///
/// This function uses heuristic scoring across all supported architectures
/// and returns the most likely classification.
pub fn analyze(data: &[u8]) -> Result<ClassificationResult> {
    analyze_with_options(data, &ClassifierOptions::new())
}

/// Analyze raw binary with custom options.
pub fn analyze_with_options(
    data: &[u8],
    options: &ClassifierOptions,
) -> Result<ClassificationResult> {
    heuristics::analyze(data, options)
}

/// Quick check if data might contain code for a specific ISA.
///
/// This is a fast preliminary check before full analysis.
pub fn quick_check_isa(data: &[u8], isa: crate::types::Isa) -> bool {
    use crate::types::Isa;
    
    if data.len() < 4 {
        return false;
    }

    match isa {
        Isa::X86 | Isa::X86_64 => {
            // Look for common x86 patterns
            data.iter().take(1000).any(|&b| {
                matches!(b, 
                    0x55 |  // push ebp/rbp
                    0x90 |  // nop
                    0xC3 |  // ret
                    0xCC    // int3
                )
            })
        }
        
        Isa::AArch64 => {
            // Check for 4-byte alignment and common patterns
            if data.len() < 4 {
                return false;
            }
            
            for i in (0..data.len().min(1000)).step_by(4) {
                if i + 4 > data.len() {
                    break;
                }
                let word = u32::from_le_bytes([
                    data[i], data[i + 1], data[i + 2], data[i + 3]
                ]);
                
                // NOP, RET, or common branch patterns
                if word == 0xD503201F || word == 0xD65F03C0 || (word >> 26) == 0x25 {
                    return true;
                }
            }
            false
        }
        
        Isa::Arm => {
            // Look for ARM condition codes (E = always)
            if data.len() < 4 {
                return false;
            }
            
            for i in (0..data.len().min(1000)).step_by(4) {
                if i + 4 > data.len() {
                    break;
                }
                let word = u32::from_le_bytes([
                    data[i], data[i + 1], data[i + 2], data[i + 3]
                ]);
                
                // Check condition field (should be 0-14)
                let cond = (word >> 28) & 0xF;
                if cond == 0xE {
                    // Common ARM instructions
                    if word == 0xE1A00000 || word == 0xE12FFF1E {
                        return true;
                    }
                }
            }
            false
        }
        
        Isa::RiscV32 | Isa::RiscV64 => {
            // Look for RISC-V patterns
            let limit = data.len().min(1000);
            for i in 0..limit {
                // Check for 32-bit instruction (bits [1:0] = 11)
                if data[i] & 0x03 == 0x03 && i + 4 <= limit {
                    let word = u32::from_le_bytes([
                        data[i], data[i + 1], data[i + 2], data[i + 3]
                    ]);
                    
                    // NOP (addi x0,x0,0) or RET
                    if word == 0x00000013 || word == 0x00008067 {
                        return true;
                    }
                }
                
                // Check for compressed instruction
                if data[i] & 0x03 != 0x03 && i + 2 <= limit {
                    let half = u16::from_le_bytes([data[i], data[i + 1]]);
                    
                    // C.NOP or C.RET
                    if half == 0x0001 || half == 0x8082 {
                        return true;
                    }
                }
            }
            false
        }
        
        Isa::Mips | Isa::Mips64 => {
            // Check for MIPS patterns (big-endian check first)
            for i in (0..data.len().min(1000)).step_by(4) {
                if i + 4 > data.len() {
                    break;
                }
                
                // Try big-endian
                let word_be = u32::from_be_bytes([
                    data[i], data[i + 1], data[i + 2], data[i + 3]
                ]);
                
                // NOP or JR $ra
                if word_be == 0x00000000 || word_be == 0x03E00008 {
                    return true;
                }
                
                // Try little-endian
                let word_le = u32::from_le_bytes([
                    data[i], data[i + 1], data[i + 2], data[i + 3]
                ]);
                
                if word_le == 0x00000000 || word_le == 0x03E00008 {
                    return true;
                }
            }
            false
        }
        
        Isa::Ppc | Isa::Ppc64 => {
            // PowerPC is big-endian
            for i in (0..data.len().min(1000)).step_by(4) {
                if i + 4 > data.len() {
                    break;
                }
                
                let word = u32::from_be_bytes([
                    data[i], data[i + 1], data[i + 2], data[i + 3]
                ]);
                
                // NOP or BLR
                if word == 0x60000000 || word == 0x4E800020 {
                    return true;
                }
            }
            false
        }
        
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Isa;

    #[test]
    fn test_quick_check_x86() {
        let data = [0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3];
        assert!(quick_check_isa(&data, Isa::X86_64));
    }

    #[test]
    fn test_quick_check_aarch64() {
        // NOP (D503201F) in little-endian
        let data = [0x1F, 0x20, 0x03, 0xD5];
        assert!(quick_check_isa(&data, Isa::AArch64));
    }

    #[test]
    fn test_quick_check_riscv() {
        // NOP (00000013) in little-endian
        let data = [0x13, 0x00, 0x00, 0x00];
        assert!(quick_check_isa(&data, Isa::RiscV64));
    }
}
