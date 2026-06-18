import sys

addr = sys.argv[1]

if addr.startswith('0x'):
    addr = addr[2:]

addr = int(addr, base=16)

pml4 = (addr >> 39) & 0x1FF;
pdpt = (addr >> 30) & 0x1FF;
pd = (addr >> 21) & 0x1FF;
pt = (addr >> 12) & 0x1FF;

print(f"Address: 0x{addr:016x}")

print("PML4 index: ", pml4)
print("PDPT index: ", pdpt)
print("PD   index: ", pd)
print("PT   index: ", pt)


RPML4T = 0xFFFF_FF7F_BFDF_E000;
RPDPT = 0xFFFF_FF7F_BFC0_0000;
RPDT = 0xFFFF_FF7F_8000_0000;
RPT = 0xFFFF_FF00_0000_0000;

print(f"PML4 RAW: x/2 0x{(RPML4T + (pml4 * 8)):016x}")
print(f"PDPT RAW: x/2 0x{(RPDPT + (pml4 << 12) + (pdpt * 8)):016x}")
print(f"PD   RAW: x/2 0x{(RPDT + (pml4 << 21) + (pdpt << 12) + (pd * 8)):016x}")
print(f"PD   RAW: x/2 0x{(RPT + (pml4 << 30) + (pdpt << 21) + (pd << 12) + (pt * 8)):016x}")
