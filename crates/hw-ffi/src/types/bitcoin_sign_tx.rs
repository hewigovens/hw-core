use hw_wallet::btc::{
    TxInput, TxInputHDNodePath, TxInputHDNodeRef, TxInputInput, TxInputMultisig,
    TxInputMultisigPubkeysOrder, TxInputOutput, TxInputRefTx, TxInputRefTxInput,
    TxInputRefTxOutput,
};
use trezor_connect::thp::{BtcInputScriptType, BtcOutputScriptType, BtcSignTx};

use crate::errors::HWCoreError;

/// Bitcoin transaction to sign, with the previous transactions its inputs spend.
#[derive(uniffi::Record, Clone, Debug)]
pub struct BitcoinSignTxRequest {
    pub inputs: Vec<BitcoinTxInput>,
    pub outputs: Vec<BitcoinTxOutput>,
    /// Every transaction an input spends from; the device verifies amounts against them.
    pub ref_txs: Vec<BitcoinRefTx>,
    pub version: u32,
    pub lock_time: u32,
    pub chunkify: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct BitcoinTxInput {
    /// BIP32 path of the key that signs this input, e.g. `m/84'/0'/0'/0/1`.
    pub path: String,
    /// Hex txid of the transaction this input spends.
    pub prev_hash: String,
    pub prev_index: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// `None` uses `0xffffffff`.
    pub sequence: Option<u32>,
    /// `External` is rejected: it needs metadata this record does not carry.
    pub script_type: BtcInputScriptType,
    /// Required for `SpendMultisig`.
    #[uniffi(default = None)]
    pub multisig: Option<BitcoinMultisig>,
}

/// Payment to `address`, or change back to the wallet at `path`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct BitcoinTxOutput {
    pub address: Option<String>,
    pub path: Option<String>,
    /// Amount in satoshis.
    pub amount: u64,
    /// `None` infers it: PayToAddress for an address, from the path purpose for change.
    pub script_type: Option<BtcOutputScriptType>,
    /// Hex payload for a PayToOpReturn output.
    pub op_return_data: Option<String>,
    /// Required for `PayToMultisig` change.
    #[uniffi(default = None)]
    pub multisig: Option<BitcoinMultisig>,
}

/// Multisig redeem script description: `m` of the cosigner keys in `pubkeys`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct BitcoinMultisig {
    pub pubkeys: Vec<BitcoinMultisigPubkey>,
    /// Hex signatures already collected from other cosigners, one slot per pubkey (empty if none).
    pub signatures: Vec<String>,
    pub m: u32,
    pub pubkeys_order: BitcoinMultisigPubkeysOrder,
}

/// A cosigner's account xpub and the non-hardened path below it, e.g. `[0, 5]`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct BitcoinMultisigPubkey {
    pub xpub: String,
    pub address_n: Vec<u32>,
}

#[derive(uniffi::Enum, Clone, Copy, Debug)]
pub enum BitcoinMultisigPubkeysOrder {
    Preserved,
    /// BIP-67 sorted, as `sortedmulti` descriptors use.
    Lexicographic,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct BitcoinRefTx {
    /// Hex txid.
    pub hash: String,
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<BitcoinRefTxInput>,
    pub bin_outputs: Vec<BitcoinRefTxOutput>,
    pub extra_data: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct BitcoinRefTxInput {
    pub prev_hash: String,
    pub prev_index: u32,
    /// Hex scriptSig.
    pub script_sig: String,
    pub sequence: Option<u32>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct BitcoinRefTxOutput {
    pub amount: u64,
    /// Hex scriptPubKey.
    pub script_pubkey: String,
}

#[uniffi::remote(Enum)]
pub enum BtcInputScriptType {
    SpendAddress,
    SpendMultisig,
    External,
    SpendWitness,
    SpendP2shWitness,
    SpendTaproot,
}

#[uniffi::remote(Enum)]
pub enum BtcOutputScriptType {
    PayToAddress,
    PayToScriptHash,
    PayToMultisig,
    PayToOpReturn,
    PayToWitness,
    PayToP2shWitness,
    PayToTaproot,
}

/// Name `hw_wallet::btc` parses, so typed requests share the JSON path's validation.
trait ScriptTypeName {
    fn wallet_name(&self) -> &'static str;
}

impl ScriptTypeName for BtcInputScriptType {
    fn wallet_name(&self) -> &'static str {
        match self {
            Self::SpendAddress => "spendaddress",
            Self::SpendMultisig => "spendmultisig",
            Self::External => "external",
            Self::SpendWitness => "spendwitness",
            Self::SpendP2shWitness => "spendp2shwitness",
            Self::SpendTaproot => "spendtaproot",
        }
    }
}

impl ScriptTypeName for BtcOutputScriptType {
    fn wallet_name(&self) -> &'static str {
        match self {
            Self::PayToAddress => "paytoaddress",
            Self::PayToScriptHash => "paytoscripthash",
            Self::PayToMultisig => "paytomultisig",
            Self::PayToOpReturn => "paytoopreturn",
            Self::PayToWitness => "paytowitness",
            Self::PayToP2shWitness => "paytop2shwitness",
            Self::PayToTaproot => "paytotaproot",
        }
    }
}

const DEFAULT_SEQUENCE: u32 = 0xffff_ffff;

impl TryFrom<BitcoinSignTxRequest> for BtcSignTx {
    type Error = HWCoreError;

    fn try_from(request: BitcoinSignTxRequest) -> Result<Self, Self::Error> {
        // External inputs need a scriptPubKey, signatures and an ownership proof this record does not carry.
        if request
            .inputs
            .iter()
            .any(|input| input.script_type == BtcInputScriptType::External)
        {
            return Err(HWCoreError::Validation(
                "External inputs are not supported in typed Bitcoin requests; use the JSON sign_tx path"
                    .into(),
            ));
        }
        Ok(BtcSignTx::try_from(TxInput::from(request))?)
    }
}

impl From<BitcoinSignTxRequest> for TxInput {
    fn from(request: BitcoinSignTxRequest) -> Self {
        Self {
            version: request.version,
            lock_time: request.lock_time,
            chunkify: request.chunkify,
            inputs: request.inputs.into_iter().map(Into::into).collect(),
            outputs: request.outputs.into_iter().map(Into::into).collect(),
            ref_txs: request.ref_txs.into_iter().map(Into::into).collect(),
            orig_txs: Vec::new(),
            payment_reqs: Vec::new(),
        }
    }
}

impl From<BitcoinTxInput> for TxInputInput {
    fn from(input: BitcoinTxInput) -> Self {
        Self {
            path: input.path,
            prev_hash: input.prev_hash,
            prev_index: input.prev_index,
            amount: input.amount.to_string(),
            sequence: input.sequence.unwrap_or(DEFAULT_SEQUENCE),
            script_type: input.script_type.wallet_name().to_string(),
            multisig: input.multisig.map(Into::into),
            script_sig: None,
            witness: None,
            orig_hash: None,
            orig_index: None,
        }
    }
}

impl From<BitcoinTxOutput> for TxInputOutput {
    fn from(output: BitcoinTxOutput) -> Self {
        Self {
            address: output.address,
            path: output.path,
            amount: output.amount.to_string(),
            script_type: output
                .script_type
                .map(|script_type| script_type.wallet_name().to_string()),
            multisig: output.multisig.map(Into::into),
            op_return_data: output.op_return_data,
            orig_hash: None,
            orig_index: None,
            payment_req_index: None,
        }
    }
}

impl From<BitcoinMultisig> for TxInputMultisig {
    fn from(multisig: BitcoinMultisig) -> Self {
        Self {
            pubkeys: multisig
                .pubkeys
                .into_iter()
                .map(|pubkey| TxInputHDNodePath {
                    node: TxInputHDNodeRef::Xpub(pubkey.xpub),
                    address_n: pubkey.address_n,
                })
                .collect(),
            signatures: multisig.signatures,
            m: multisig.m,
            nodes: Vec::new(),
            address_n: Vec::new(),
            pubkeys_order: match multisig.pubkeys_order {
                BitcoinMultisigPubkeysOrder::Preserved => TxInputMultisigPubkeysOrder::Preserved,
                BitcoinMultisigPubkeysOrder::Lexicographic => {
                    TxInputMultisigPubkeysOrder::Lexicographic
                }
            },
        }
    }
}

impl From<BitcoinRefTx> for TxInputRefTx {
    fn from(tx: BitcoinRefTx) -> Self {
        Self {
            hash: tx.hash,
            version: tx.version,
            lock_time: tx.lock_time,
            inputs: tx
                .inputs
                .into_iter()
                .map(|input| TxInputRefTxInput {
                    prev_hash: input.prev_hash,
                    prev_index: input.prev_index,
                    script_sig: input.script_sig,
                    sequence: input.sequence.unwrap_or(DEFAULT_SEQUENCE),
                })
                .collect(),
            bin_outputs: tx
                .bin_outputs
                .into_iter()
                .map(|output| TxInputRefTxOutput {
                    amount: output.amount.to_string(),
                    script_pubkey: output.script_pubkey,
                })
                .collect(),
            extra_data: tx.extra_data,
            timestamp: None,
            version_group_id: None,
            expiry: None,
            branch_id: None,
        }
    }
}
