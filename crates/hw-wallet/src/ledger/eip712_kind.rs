/// Ledger's EIP-712 field discriminator (before size and array flags).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Eip712Kind {
    Struct = 0,
    Int = 1,
    Uint = 2,
    Address = 3,
    Bool = 4,
    String = 5,
    FixedBytes = 6,
    Bytes = 7,
}
