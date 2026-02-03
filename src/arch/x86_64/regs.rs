use core::fmt::Debug;

#[repr(C, packed(8))]
pub struct CPURegisters {
    pub ds: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub int_num: u64,
    pub err_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub userrsp: u64,
    pub ss: u64,
}

impl Debug for CPURegisters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Registers (x86_64):\n")?;

        write!(f, "RAX: {:016x}; RBX: {:016x}\n", self.rax, self.rbx)?;
        write!(f, "RCX: {:016x}; RDX: {:016x}\n", self.rcx, self.rdx)?;
        write!(f, "RSI: {:016x}; RDI: {:016x}\n", self.rsi, self.rdi)?;
        write!(f, "RSP: {:016x}; RBP: {:016x}\n", self.rsp, self.rbp)?;
        write!(f, "R8:  {:016x}; R9:  {:016x}\n", self.r8, self.r9)?;
        write!(f, "R10: {:016x}; R11: {:016x}\n", self.r10, self.r11)?;
        write!(f, "R12: {:016x}; R13: {:016x}\n", self.r12, self.r13)?;
        write!(f, "R14: {:016x}; R15: {:016x}\n", self.r14, self.r15)?;
        write!(f, "EIP: {:08x}\n", self.rip)?;
        write!(f, "CS:  {:04x}; DS: {:04x}\n", self.cs, self.ds)?;
        write!(f, "EFLAGS: {:08x}\n", self.rflags)?;
        write!(f, "INTERRUPT: {:02x}; ERROR: {:08x}", self.int_num, self.err_code)?;

        Ok(())
    }
}
