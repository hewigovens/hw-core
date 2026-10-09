/// Which transaction an input or output belongs to; it names the fields in validation errors.
#[derive(Debug, Clone, Copy)]
pub(super) enum TxOwner {
    Signing,
    Original,
}

impl TxOwner {
    pub(super) fn output_label(self) -> &'static str {
        match self {
            Self::Signing => "bitcoin output",
            Self::Original => "bitcoin original tx output",
        }
    }

    pub(super) fn input_prev_hash_field(self) -> &'static str {
        match self {
            Self::Signing => "prev_hash",
            Self::Original => "orig_txs.inputs.prev_hash",
        }
    }

    pub(super) fn input_orig_hash_field(self) -> &'static str {
        match self {
            Self::Signing => "inputs.orig_hash",
            Self::Original => "orig_txs.inputs.orig_hash",
        }
    }

    pub(super) fn output_orig_hash_field(self) -> &'static str {
        match self {
            Self::Signing => "outputs.orig_hash",
            Self::Original => "orig_txs.outputs.orig_hash",
        }
    }
}
