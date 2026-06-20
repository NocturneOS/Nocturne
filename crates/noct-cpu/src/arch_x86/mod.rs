pub mod gdt;
pub mod halt;
pub mod idt;

pub mod tss;

use core::fmt::Debug;

#[repr(C, packed(4))]
pub struct CPURegisters {
    pub ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub int_num: u32,
    pub err_code: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub useresp: u32,
    pub ss: u32,
}

impl Debug for CPURegisters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Registers (x86):\n")?;

        writeln!(f, "EAX: {:08x}; EBX: {:08x}", self.eax, self.ebx)?;
        writeln!(f, "ECX: {:08x}; EDX: {:08x}", self.ecx, self.edx)?;
        writeln!(f, "ESI: {:08x}; EDI: {:08x}", self.esi, self.edi)?;
        writeln!(f, "ESP: {:08x}; EBP: {:08x}", self.esp, self.ebp)?;
        writeln!(f, "EIP: {:08x}", self.eip)?;
        writeln!(f, "CS:  {:04x}; DS: {:04x}", self.cs, self.ds)?;
        writeln!(f, "EFLAGS: {:08x}", self.eflags)?;
        write!(
            f,
            "INTERRUPT: {:02x}; ERROR: {:08x}",
            self.int_num, self.err_code
        )?;

        Ok(())
    }
}
