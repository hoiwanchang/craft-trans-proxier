//! Minimal but conservative x86-64 instruction-length decoder.
//!
//! The inline "Module Copy" hook (finding fnd_7) must displace a WHOLE number of
//! instructions from the target function's prologue — overwriting a partial
//! instruction corrupts memory and crashes, which is precisely what the original
//! the original guards against with its "cannot decode instructions … switch to
//! Module Copy" error. A faithful decoder is therefore required, not optional.
//!
//! This covers the instruction forms that actually appear in Win32/WinSock
//! function prologues (REX, common one/two/three-byte opcodes, ModRM/SIB/disp,
//! immediate operands). Anything it is not sure about returns `None`, and the
//! caller then declines to hook (a safe no-op) rather than guess. It is NOT a
//! full ISA decoder by design: it errs only toward refusal, never toward a wrong
//! length.

/// Decode whole instructions from the start of `code`, accumulating bytes, until
/// at least `need` bytes are covered, and return that total length. Refuses
/// (None) if any covered instruction is a near-relative control transfer we
/// cannot relocate, or anything is undecodable. This is the displacement step of
/// the inline hook.
pub fn displace_window(code: &[u8], need: usize) -> Option<usize> {
    displace(code, need).map(|(len, _)| len)
}

/// Where a 4-byte RIP-relative displacement sits inside a displaced prologue,
/// and where the instruction carrying it ends (= the RIP it is relative to).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RipFixup {
    pub disp_at: usize,
    pub insn_end: usize,
}

/// `displace_window` plus the RIP-relative operands found in the displaced
/// bytes: copying them verbatim to a trampoline page silently repoints every
/// `[rip+disp32]` at unrelated memory, so the installer must correct each one.
pub fn displace(code: &[u8], need: usize) -> Option<(usize, Vec<RipFixup>)> {
    let mut off = 0usize;
    let mut fixups = Vec::new();
    while off < need {
        let (ilen, op, op2, local) = decode_insn_full(&code[off..])?;
        let rel_branch = matches!(op, 0xE8 | 0xE9 | 0xEB)
            || (0x70..=0x7F).contains(&op)
            || (op == 0x0F && (0x80..=0x8F).contains(&op2));
        if rel_branch {
            return None;
        }
        for f in local {
            fixups.push(RipFixup { disp_at: f.disp_at + off, insn_end: f.insn_end + off });
        }
        off += ilen;
    }
    Some((off, fixups))
}

/// A `rel8` branch found inside a prologue we want to steal, recorded so the installer
/// can widen it to the `rel32` form while copying (a 2-byte `je +0x56` cannot survive a
/// move to another page, but `0F 84 disp32` can).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortBranch {
    /// offset of the instruction inside the window
    pub at: usize,
    /// offset just past it — the RIP its displacement is relative to
    pub insn_end: usize,
    /// `EB` (unconditional, widens to `E9 rel32`) rather than `70..=7F` (widens to
    /// `0F 8x rel32`)
    pub unconditional: bool,
    /// condition code for the `jcc` form (`op & 0x0F`)
    pub cc: u8,
    /// the displacement exactly as encoded
    pub rel: i8,
}

/// [`displace`], but *accepting* `rel8` branches (70-7F / EB) and reporting them for
/// widening. This is the difference between hooking an entry point and refusing it:
/// ws2_32!`freeaddrinfo` opens with `48 85 c9` (`test rcx,rcx`) + `74 56` (`je +0x56`),
/// so a plain decoder refuses to steal even 5 bytes, and the `freeaddrinfo` half of the
/// getaddrinfo pair — and therefore DNS fake-IP — would stay un-installed.
///
/// Anything it cannot re-encode still causes a refusal, so nothing gets riskier:
/// `E8`/`E9`/`0F 80..8F` (already `rel32`, and a call would need the target's own
/// bookkeeping) and undecodable bytes all return `None`.
pub fn displace_widenable(code: &[u8], need: usize) -> Option<(usize, Vec<RipFixup>, Vec<ShortBranch>)> {
    let mut off = 0usize;
    let mut fixups = Vec::new();
    let mut branches = Vec::new();
    while off < need {
        let (ilen, op, op2, local) = decode_insn_full(&code[off..])?;
        if op == 0xE8 || op == 0xE9 || (op == 0x0F && (0x80..=0x8F).contains(&op2)) {
            return None;
        }
        if op == 0xEB || (0x70..=0x7F).contains(&op) {
            // The displacement of a rel8 branch is its final byte, whichever legacy
            // prefix (0x2E and friends) precedes the opcode.
            let rel = *code.get(off + ilen - 1)? as i8;
            branches.push(ShortBranch {
                at: off,
                insn_end: off + ilen,
                unconditional: op == 0xEB,
                cc: op & 0x0F,
                rel,
            });
        }
        for f in local {
            fixups.push(RipFixup {
                disp_at: f.disp_at + off,
                insn_end: f.insn_end + off,
            });
        }
        off += ilen;
    }
    Some((off, fixups, branches))
}

/// Length of one instruction at `code`, or `None` if it cannot be decoded
/// confidently. `code` must have at least 16 readable bytes (a guard window).
pub fn insn_len(code: &[u8]) -> Option<usize> {
    decode_insn(code).map(|(len, _, _)| len)
}

/// Decode one instruction, returning (total length, primary opcode, secondary
/// opcode byte). The caller uses the opcodes to refuse relocating near relative
/// branches (E8/E9/EB/70-7F/jcc, and 0F 80-8F) into a trampoline.
pub fn decode_insn(code: &[u8]) -> Option<(usize, u8, u8)> {
    decode_insn_full(code).map(|(n, op, op2, _)| (n, op, op2))
}

/// As `decode_insn`, plus the RIP-relative operands of this one instruction.
pub fn decode_insn_full(code: &[u8]) -> Option<(usize, u8, u8, Vec<RipFixup>)> {
    let mut fixups = Vec::new();
    let n = insn_len_inner(code, &mut fixups)?;
    // Locate the primary opcode (past one REX + any legacy prefixes).
    let mut j = 0usize;
    if j < code.len() && (0x40..=0x4F).contains(&code[j]) {
        j += 1;
    }
    loop {
        if j >= code.len() {
            return None;
        }
        match code[j] {
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => j += 1,
            _ => break,
        }
    }
    let op = code[j];
    let op2 = if j + 1 < code.len() { code[j + 1] } else { 0 };
    Some((n, op, op2, fixups))
}

fn insn_len_inner(code: &[u8], fix: &mut Vec<RipFixup>) -> Option<usize> {
    // i686 has no RIP-relative addressing, so no fixups are ever recorded there.
    let _ = &fix;
    let mut i = 0usize;

    // 1. REX prefixes (0x40..=0x4F) exist only in 64-bit mode, immediately before
    //    the opcode. On i686 these bytes are inc/dec reg (handled below).
    #[cfg(target_arch = "x86_64")]
    let rex_w = {
        let mut w = false;
        if i < code.len() && (0x40..=0x4F).contains(&code[i]) {
            w = code[i] & 0x08 != 0;
            i += 1;
        }
        w
    };
    #[cfg(not(target_arch = "x86_64"))]
    let rex_w = false;

    // 2. Operand/address size prefixes + segment/lock prefixes.
    let mut op_size16 = false;
    let mut have_prefix = true;
    while have_prefix && i < code.len() {
        match code[i] {
            0x66 => op_size16 = true,
            0x67 => return None, // address-size override: rare in prologues, refuse
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => {}
            _ => have_prefix = false,
        }
        if have_prefix {
            i += 1;
        }
    }
    if i >= code.len() {
        return None;
    }

    let op = code[i];
    i += 1;

    // imm widths driven by the operand-size / REX.W.
    let immv = if op_size16 { 2 } else { 4 }; // "v" immediate size
    // MOV r64, imm64 (REX.W B8+r) uses a full 8-byte immediate.
    if rex_w && (0xB8..=0xBF).contains(&op) {
        return Some(i + 8);
    }

    // Two-byte escape (0F): size the common prologue forms; refuse the rest.
    if op == 0x0F {
        if i >= code.len() {
            return None;
        }
        let o2 = code[i];
        i += 1;
        match o2 {
            // no-ModRM forms: syscall, rdtsc, rdtscp, ud2, clac/stac/swapyls…
            0x05 | 0x06 | 0x07 | 0x08 | 0x30 | 0x31 | 0x34 | 0x35 => return Some(i),
            // 0F 1E FA/FB = endbr64/endbr32 (CET, ModRM with reg=7, no memory operand)
            0x1E => {
                if i >= code.len() {
                    return None;
                }
                let m = code[i];
                i += 1;
                if (m >> 3) & 0b111 != 7 {
                    return None; // a real memory 0F 1E form (CET/nop) we don't size
                }
                return Some(i);
            }
            // jcc rel32 (a near branch — the installer refuses to relocate it)
            0x80..=0x8F => return Some(i + 4),
            // ModRM-carrying, no immediate: cmovcc, movzx/movsx, imul r,r/m,
            // bt/bts mem, setcc, xchg, lea-like nops.
            0x40..=0x4F | 0x90..=0x9F | 0xA3 | 0xAB | 0xAF | 0xB0..=0xB7 | 0xBE..=0xBF
            | 0x1F => {
                if i >= code.len() {
                    return None;
                }
                let modrm = code[i];
                i += 1;
                let md = modrm >> 6;
                let rm = modrm & 0b111;
                let mut disp = 0usize;
                #[cfg(target_arch = "x86_64")]
                let mut rip_at = None;
                if md == 0 && rm == 5 {
                    disp = 4;
                    #[cfg(target_arch = "x86_64")]
                    {
                        rip_at = Some(i);
                    }
                } else if md != 3 && rm == 4 {
                    if i >= code.len() {
                        return None;
                    }
                    let sib = code[i];
                    i += 1;
                    if md == 0 && (sib & 0b111) == 5 {
                        disp = 4;
                    }
                }
                match md {
                    1 => disp = disp.max(1),
                    2 => disp = disp.max(4),
                    _ => {}
                }
                i += disp;
                #[cfg(target_arch = "x86_64")]
                if let Some(d) = rip_at {
                    fix.push(RipFixup { disp_at: d, insn_end: i });
                }
                return Some(i);
            }
            _ => return None,
        }
    }

    // No-modrm one-byte opcodes with fixed operand shapes.
    match op {
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C | 0x6A | 0xA8 | 0xCD => {
            return Some(i + 1) // imm8
        }
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D | 0x68 | 0xA9 => {
            return Some(i + immv) // imm16/32
        }
        0x50..=0x5F | 0x90 | 0x98 | 0x99 | 0x9B | 0x9C | 0x9D | 0xC3 | 0xC9 | 0xCC | 0xF5 => {
            return Some(i)
        }
        // On i686, 0x40..=0x4F are inc/dec reg (no operand). In 64-bit mode they
        // were consumed as REX above and never reach here.
        #[cfg(target_arch = "x86")]
        0x40..=0x4F => return Some(i),
        0xC2 => return Some(i + 2),         // ret imm16
        0x70..=0x7F => return Some(i + 1),  // jcc rel8
        0xEB => return Some(i + 1),         // jmp short rel8
        0xE8 | 0xE9 => return Some(i + 4),  // call/jmp near rel32
        _ => {}
    }

    // Most remaining opcodes carry a ModRM byte. Group1/ALU/lea/mov/cmp/test …
    if needs_modrm(op) {
        if i >= code.len() {
            return None;
        }
        let modrm = code[i];
        i += 1;
        let mod_ = modrm >> 6;
        let rm = modrm & 0b111;
        let mut disp = 0usize;
        #[cfg(target_arch = "x86_64")]
        let mut rip_at = None;

        if mod_ == 0 && rm == 5 {
            disp = 4; // RIP-relative disp32
            #[cfg(target_arch = "x86_64")]
            {
                rip_at = Some(i);
            }
        } else if mod_ != 3 && rm == 4 {
            // SIB byte present (only when mod != 3; mod==3 & rm==4 is register r12).
            if i >= code.len() {
                return None;
            }
            let sib = code[i];
            i += 1;
            let base = sib & 0b111;
            if mod_ == 0 && base == 5 {
                disp = 4; // disp32 with no base
            }
        }
        match mod_ {
            1 => disp = 1,
            2 => disp = 4,
            _ => {}
        }
        i += disp;

        // Immediate that follows, if this opcode group carries one.
        i += trailing_imm(op, immv)?;
        #[cfg(target_arch = "x86_64")]
        if let Some(d) = rip_at {
            fix.push(RipFixup { disp_at: d, insn_end: i });
        }
        return Some(i);
    }

    // Unknown/undecodable opcode form: refuse rather than guess.
    None
}

/// Opcodes whose instruction carries a ModRM byte (and were not already sized
/// by the no-modrm fast paths above).
fn needs_modrm(op: u8) -> bool {
    // Conservative table: returns true for opcode classes that use a ModRM byte
    // and that we otherwise did not already handle.
    matches!(op,
        0x00..=0x03 | 0x08..=0x0B | 0x10..=0x13 | 0x18..=0x1B
        | 0x20..=0x23 | 0x28..=0x2B | 0x30..=0x33 | 0x38..=0x3B
        | 0x60..=0x63
        | 0x69 | 0x6B
        | 0x80..=0x8F
        | 0xC0..=0xC1 | 0xC6..=0xC7
        | 0xD0..=0xD3
        | 0xF6..=0xF7
        | 0xFE | 0xFF
    )
}

/// Immediate bytes that FOLLOW a ModRM-encoded instruction, keyed by opcode.
/// Returns None for opcodes this decoder does not fully size.
fn trailing_imm(op: u8, immv: usize) -> Option<usize> {
    let n = match op {
        // Group1 / two-operand ALU+reg,r/m and r/m,imm
        0x80 | 0x83 | 0xC0 | 0xC1 | 0xD0 | 0xD1 | 0xD2 | 0xD3 | 0xF6 | 0xFE => 1, // imm8
        0x81 => immv,
        0x69 => immv,
        0x6B => 1,
        0xC6 => 1,
        0xC7 => immv,
        // mov/load/store without immediates
        0x00..=0x03 | 0x08..=0x0B | 0x10..=0x13 | 0x18..=0x1B | 0x20..=0x23
        | 0x28..=0x2B | 0x30..=0x33 | 0x38..=0x3B | 0x60..=0x63 | 0x84..=0x8F
        | 0xD8..=0xDF => 0,
        // F7 is group: test has immv, others none — approximate & refuse for F7
        0xF7 => return None,
        0xFF => 0, // inc/dec/call/jmp/push (no immediate)
        _ => return None,
    };
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real prologue of ws2_32!freeaddrinfo on the development host, captured
    /// 2026-11-25: `test rcx,rcx` + `je +0x56`. A near-relative branch inside the
    /// first five bytes is exactly what made this export unhookable, so the bytes
    /// stay here as a fixture rather than in a comment.
    const FREEADDRINFO: [u8; 20] = [
        0x48, 0x85, 0xc9, 0x74, 0x56, 0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec,
        0x20, 0x48, 0x8b, 0xd9, 0x48, 0x8b,
    ];

    #[test]
    fn a_short_branch_in_the_window_blocks_plain_displacement() {
        // Both patch shapes refuse this prologue outright — the state of things before
        // branch widening existed, and still the right answer for a plain copy.
        assert!(displace(&FREEADDRINFO, 14).is_none(), "je inside the first 5 bytes must be refused");
        assert!(displace(&FREEADDRINFO, 5).is_none(), "and it is inside 5 too");
    }

    #[test]
    fn branch_widening_reports_the_je_where_it_actually_is() {
        let (off, fixups, branches) = displace_widenable(&FREEADDRINFO, 14).expect("widenable");
        assert!(fixups.is_empty(), "this prologue carries no RIP operand");
        assert_eq!(branches.len(), 1);
        let b = branches[0];
        assert_eq!((b.at, b.insn_end), (3, 5), "opcode at 3, its RIP at 5");
        assert_eq!((b.unconditional, b.cc, b.rel), (false, 4, 0x56), "a conditional je, +0x56");
        // 15 bytes stolen (test, je, mov[rsp+8], push rdi, sub rsp) ≥ the 14 the
        // absolute patch needs — which is what makes the export hookable at all.
        assert!(off >= 14, "window must still cover the patch, got off={off}");
    }

    #[test]
    fn branch_widening_still_refuses_what_it_cannot_re_encode() {
        // rel32 forms are position-dependent in ways we do not attempt: a call, a jump,
        // and a wide jcc must all keep causing a refusal.
        let mut call = [0x90u8; 16];
        call[0] = 0xE8;
        let mut jmp = [0x90u8; 16];
        jmp[0] = 0xE9;
        let mut jcc32 = [0x90u8; 16];
        jcc32[0] = 0x0F;
        jcc32[1] = 0x84;
        for (name, p) in [("e8", call), ("e9", jmp), ("0f84", jcc32)] {
            assert!(displace_widenable(&p, 5).is_none(), "{name} must not be widened");
        }
    }

    #[test]
    fn an_unconditional_short_jump_widens_to_e9() {
        // EB 10 then filler: reported as unconditional so the builder emits E9 rel32.
        let mut code = [0x90u8; 20];
        code[0] = 0xEB;
        code[1] = 0x10;
        let (_, _, branches) = displace_widenable(&code, 14).expect("widenable");
        assert_eq!(branches.len(), 1);
        assert!(branches[0].unconditional);
        assert_eq!((branches[0].at, branches[0].insn_end, branches[0].rel), (0, 2, 0x10));
    }

    fn len(b: &[u8]) -> usize {
        // Pad so the decoder always has a guard window.
        let mut v = b.to_vec();
        v.resize(16, 0x90);
        insn_len(&v).expect("should decode")
    }

    #[test]
    fn simple_nops_and_ret() {
        assert_eq!(len(&[0x90]), 1); // nop
        assert_eq!(len(&[0xC3]), 1); // ret
        assert_eq!(len(&[0xCC]), 1); // int3
    }

    #[test]
    fn rex_mov_rm_imm() {
        // 48 89 E5 = mov rbp, rsp  (REX.W MOV r/m64, r64, ModRM C0-ish E5)
        assert_eq!(len(&[0x48, 0x89, 0xE5]), 3);
        // 48 8B 05 xx xx xx xx = mov rax, [rip+disp32]  -> 7
        assert_eq!(len(&[0x48, 0x8B, 0x05, 0, 0, 0, 0]), 7);
    }

    #[test]
    fn sub_rsp_imm32_and_call() {
        // 48 81 EC xx xx xx xx = sub rsp, imm32 -> 7
        assert_eq!(len(&[0x48, 0x81, 0xEC, 0x20, 0, 0, 0]), 7);
        // E8 rel32 call -> 5
        assert_eq!(len(&[0xE8, 0x11, 0x22, 0x33, 0x44]), 5);
        // EB rel8 jmp -> 2
        assert_eq!(len(&[0xEB, 0x05]), 2);
    }

    #[test]
    fn push_pop_and_mov_imm64() {
        // 55 push rbp -> 1
        assert_eq!(len(&[0x55]), 1);
        // 48 B8 + imm64 = mov rax, imm64 -> 10
        assert_eq!(len(&[0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8]), 10);
    }

    #[test]
    fn lea_with_sib() {
        // 4C 8D 05 rel = lea r8, [rip+disp32] -> 7
        assert_eq!(len(&[0x4C, 0x8D, 0x05, 0, 0, 0, 0]), 7);
    }

    #[test]
    fn refuses_unknown_and_addr_size() {
        // 67 address-size prefix -> refuse
        let mut v = vec![0x67, 0x90];
        v.resize(16, 0x90);
        assert!(insn_len(&v).is_none());
    }

    #[test]
    fn displacement_of_realistic_prologue() {
        // mov [rsp+8],rbx ; push rdi ; sub rsp,0x20 ; mov rax,[rdx+8]  = 14 bytes
        let mut code = vec![
            0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
            0x57,                         // push rdi
            0x48, 0x83, 0xEC, 0x20,       // sub rsp, 0x20
            0x48, 0x8B, 0x42, 0x08,       // mov rax, [rdx+8]
        ];
        code.resize(32, 0x90);
        assert_eq!(displace_window(&code, 14), Some(14));
    }

    #[test]
    fn displacement_refuses_near_branch() {
        // jmp rel32 as the very first instruction -> cannot relocate -> None
        let mut code = vec![0xE9, 0x00, 0x00, 0x00, 0x00];
        code.resize(32, 0x90);
        assert_eq!(displace_window(&code, 14), None);
        // jz rel8 (0x74) -> None
        let mut code2 = vec![0x74, 0x10];
        code2.resize(32, 0x90);
        assert_eq!(displace_window(&code2, 5), None);
    }

    #[test]
    fn endbr64_and_movzx_sizes() {
        // F3 0F 1E FA = endbr64 (4 bytes)
        assert_eq!(len(&[0xF3, 0x0F, 0x1E, 0xFA]), 4);
        // 0F B6 C0 = movzx eax, al (3 bytes)
        assert_eq!(len(&[0x0F, 0xB6, 0xC0]), 3);
        // 0F 84 rel32 = je near (6 bytes)
        assert_eq!(len(&[0x0F, 0x84, 0x11, 0x22, 0x33, 0x44]), 6);
    }
}
