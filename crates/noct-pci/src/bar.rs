#[derive(Debug, PartialEq)]
pub enum BARType {
    Memory = 0,
    IO = 1,
}

impl From<BARType> for u8 {
    fn from(val: BARType) -> Self {
        match val {
            BARType::Memory => 0,
            BARType::IO => 1,
        }
    }
}

#[derive(Debug)]
pub struct PCIBar {
    pub bar_type: BARType,
    pub address: usize,
    pub length: usize,
}
