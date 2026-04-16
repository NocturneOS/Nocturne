pub const ATA_SR_BSY: u8 =     0x80;
pub const ATA_SR_DRDY: u8 =    0x40;
pub const ATA_SR_DF: u8 =      0x20;
pub const ATA_SR_DSC: u8 =     0x10;
pub const ATA_SR_DRQ: u8 =     0x08;
pub const ATA_SR_CORR: u8 =    0x04;
pub const ATA_SR_IDX: u8 =     0x02;
pub const ATA_SR_ERR: u8 =     0x01;

pub const ATA_ER_BBK: u8 =      0x80;
pub const ATA_ER_UNC: u8 =      0x40;
pub const ATA_ER_MC: u8 =       0x20;
pub const ATA_ER_IDNF: u8 =     0x10;
pub const ATA_ER_MCR: u8 =      0x08;
pub const ATA_ER_ABRT: u8 =     0x04;
pub const ATA_ER_TK0NF: u8 =    0x02;
pub const ATA_ER_AMNF: u8 =     0x01;