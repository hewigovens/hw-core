use prost::Message;

use super::multisig::MultisigRedeemScriptTypeProto;
use super::script_type::{BitcoinInputScriptTypeProto, BitcoinOutputScriptTypeProto};
use crate::thp::proto::wire::wire_messages;
use crate::thp::proto::{EncodedMessage, WireMessage};
use crate::thp::types::{
    BtcOrigTx, BtcRefTx, BtcRefTxInput, BtcRefTxOutput, BtcSignInput, BtcSignOutput, BtcSignTx,
};

#[derive(Clone, PartialEq, Message)]
pub struct BitcoinTxAck {
    #[prost(message, optional, tag = "1")]
    pub(crate) tx: Option<BitcoinTxAckTransaction>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinTxAckTransaction {
    #[prost(uint32, optional, tag = "1")]
    pub(crate) version: Option<u32>,
    #[prost(message, repeated, tag = "2")]
    pub(crate) inputs: Vec<BitcoinTxInput>,
    #[prost(message, repeated, tag = "3")]
    pub(crate) bin_outputs: Vec<BitcoinTxOutputBin>,
    #[prost(uint32, optional, tag = "4")]
    pub(crate) lock_time: Option<u32>,
    #[prost(message, repeated, tag = "5")]
    pub(crate) outputs: Vec<BitcoinTxOutput>,
    #[prost(uint32, optional, tag = "6")]
    pub(crate) inputs_cnt: Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    pub(crate) outputs_cnt: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub(crate) extra_data: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "9")]
    pub(crate) extra_data_len: Option<u32>,
    #[prost(uint32, optional, tag = "10")]
    pub(crate) expiry: Option<u32>,
    #[prost(bool, optional, tag = "11")]
    pub(crate) overwintered: Option<bool>,
    #[prost(uint32, optional, tag = "12")]
    pub(crate) version_group_id: Option<u32>,
    #[prost(uint32, optional, tag = "13")]
    pub(crate) timestamp: Option<u32>,
    #[prost(uint32, optional, tag = "14")]
    pub(crate) branch_id: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinTxInput {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    pub(crate) address_n: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "2")]
    pub(crate) prev_hash: Vec<u8>,
    #[prost(uint32, required, tag = "3")]
    pub(crate) prev_index: u32,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub(crate) script_sig: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "5")]
    pub(crate) sequence: Option<u32>,
    #[prost(enumeration = "BitcoinInputScriptTypeProto", optional, tag = "6")]
    pub(crate) script_type: Option<i32>,
    #[prost(message, optional, tag = "7")]
    pub(crate) multisig: Option<MultisigRedeemScriptTypeProto>,
    #[prost(uint64, optional, tag = "8")]
    pub(crate) amount: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "13")]
    pub(crate) witness: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "16")]
    pub(crate) orig_hash: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "17")]
    pub(crate) orig_index: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinTxOutputBin {
    #[prost(uint64, required, tag = "1")]
    pub(crate) amount: u64,
    #[prost(bytes = "vec", required, tag = "2")]
    pub(crate) script_pubkey: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinTxOutput {
    #[prost(string, optional, tag = "1")]
    pub(crate) address: Option<String>,
    #[prost(uint32, repeated, packed = "false", tag = "2")]
    pub(crate) address_n: Vec<u32>,
    #[prost(uint64, required, tag = "3")]
    pub(crate) amount: u64,
    #[prost(enumeration = "BitcoinOutputScriptTypeProto", optional, tag = "4")]
    pub(crate) script_type: Option<i32>,
    #[prost(message, optional, tag = "5")]
    pub(crate) multisig: Option<MultisigRedeemScriptTypeProto>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub(crate) op_return_data: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "10")]
    pub(crate) orig_hash: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "11")]
    pub(crate) orig_index: Option<u32>,
    #[prost(uint32, optional, tag = "12")]
    pub(crate) payment_req_index: Option<u32>,
}

wire_messages! {
    BitcoinTxAck = 22,
}

/// Answers a Bitcoin `TxRequest` with the requested part of a transaction.
pub trait TxAck {
    fn tx_ack(&self) -> EncodedMessage;
}

impl BitcoinTxAckTransaction {
    fn into_message(self) -> EncodedMessage {
        BitcoinTxAck { tx: Some(self) }.to_message()
    }
}

impl TxAck for BtcSignTx {
    fn tx_ack(&self) -> EncodedMessage {
        BitcoinTxAckTransaction {
            version: Some(self.version),
            lock_time: Some(self.lock_time),
            inputs_cnt: Some(self.inputs.len() as u32),
            outputs_cnt: Some(self.outputs.len() as u32),
            ..Default::default()
        }
        .into_message()
    }
}

impl TxAck for BtcOrigTx {
    fn tx_ack(&self) -> EncodedMessage {
        BitcoinTxAckTransaction {
            version: Some(self.version),
            lock_time: Some(self.lock_time),
            inputs_cnt: Some(self.inputs.len() as u32),
            outputs_cnt: Some(self.outputs.len() as u32),
            extra_data_len: self.extra_data.as_ref().map(|data| data.len() as u32),
            expiry: self.expiry,
            version_group_id: self.version_group_id,
            timestamp: self.timestamp,
            branch_id: self.branch_id,
            ..Default::default()
        }
        .into_message()
    }
}

impl TxAck for BtcRefTx {
    fn tx_ack(&self) -> EncodedMessage {
        BitcoinTxAckTransaction {
            version: Some(self.version),
            lock_time: Some(self.lock_time),
            inputs_cnt: Some(self.inputs.len() as u32),
            outputs_cnt: Some(self.bin_outputs.len() as u32),
            extra_data_len: self.extra_data.as_ref().map(|data| data.len() as u32),
            expiry: self.expiry,
            version_group_id: self.version_group_id,
            timestamp: self.timestamp,
            branch_id: self.branch_id,
            ..Default::default()
        }
        .into_message()
    }
}

impl TxAck for BtcSignInput {
    fn tx_ack(&self) -> EncodedMessage {
        let input = BitcoinTxInput {
            address_n: self.path.clone(),
            prev_hash: self.prev_hash.clone(),
            prev_index: self.prev_index,
            script_sig: self.script_sig.clone(),
            sequence: Some(self.sequence),
            script_type: Some(BitcoinInputScriptTypeProto::wire(self.script_type)),
            multisig: self.multisig.as_ref().map(Into::into),
            amount: Some(self.amount),
            witness: self.witness.clone(),
            orig_hash: self.orig_hash.clone(),
            orig_index: self.orig_index,
        };
        BitcoinTxAckTransaction {
            inputs: vec![input],
            ..Default::default()
        }
        .into_message()
    }
}

impl TxAck for BtcSignOutput {
    fn tx_ack(&self) -> EncodedMessage {
        let output = BitcoinTxOutput {
            address: self.address.clone(),
            address_n: self.path.clone(),
            amount: self.amount,
            script_type: Some(BitcoinOutputScriptTypeProto::from(self.script_type) as i32),
            multisig: self.multisig.as_ref().map(Into::into),
            op_return_data: self.op_return_data.clone(),
            orig_hash: self.orig_hash.clone(),
            orig_index: self.orig_index,
            payment_req_index: self.payment_req_index,
        };
        BitcoinTxAckTransaction {
            outputs: vec![output],
            ..Default::default()
        }
        .into_message()
    }
}

impl TxAck for BtcRefTxInput {
    fn tx_ack(&self) -> EncodedMessage {
        let input = BitcoinTxInput {
            prev_hash: self.prev_hash.clone(),
            prev_index: self.prev_index,
            script_sig: Some(self.script_sig.clone()),
            sequence: Some(self.sequence),
            ..Default::default()
        };
        BitcoinTxAckTransaction {
            inputs: vec![input],
            ..Default::default()
        }
        .into_message()
    }
}

impl TxAck for BtcRefTxOutput {
    fn tx_ack(&self) -> EncodedMessage {
        let output = BitcoinTxOutputBin {
            amount: self.amount,
            script_pubkey: self.script_pubkey.clone(),
        };
        BitcoinTxAckTransaction {
            bin_outputs: vec![output],
            ..Default::default()
        }
        .into_message()
    }
}

/// An `extra_data` chunk of a previous transaction.
impl TxAck for [u8] {
    fn tx_ack(&self) -> EncodedMessage {
        BitcoinTxAckTransaction {
            extra_data: Some(self.to_vec()),
            ..Default::default()
        }
        .into_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::proto::bitcoin::multisig::MultisigPubkeysOrderProto;
    use crate::thp::types::{
        BtcHDNode, BtcHDNodePath, BtcInputScriptType, BtcMultisig, BtcMultisigPubkeysOrder,
        BtcOutputScriptType,
    };

    fn decode_tx(encoded: EncodedMessage) -> BitcoinTxAckTransaction {
        assert_eq!(encoded.message_type, BitcoinTxAck::MESSAGE_TYPE);
        BitcoinTxAck::decode(encoded.payload.as_slice())
            .unwrap()
            .tx
            .unwrap()
    }

    fn node(fingerprint: u32, public_key: u8) -> BtcHDNode {
        BtcHDNode {
            depth: 4,
            fingerprint,
            child_num: 0x8000_0002,
            chain_code: vec![public_key; 32],
            public_key: vec![public_key; 33],
        }
    }

    fn ref_tx() -> BtcRefTx {
        BtcRefTx {
            hash: vec![0x11; 32],
            version: 2,
            lock_time: 123,
            inputs: vec![BtcRefTxInput {
                prev_hash: vec![0x33; 32],
                prev_index: 1,
                script_sig: vec![0x01, 0x02, 0x03],
                sequence: 0xffff_fffd,
            }],
            bin_outputs: vec![BtcRefTxOutput {
                amount: 123,
                script_pubkey: vec![0x51, 0x21],
            }],
            extra_data: Some(vec![0xde, 0xad, 0xbe, 0xef]),
            timestamp: Some(42),
            version_group_id: Some(7),
            expiry: Some(9),
            branch_id: Some(11),
        }
    }

    #[test]
    fn encodes_previous_transaction_parts() {
        let tx = ref_tx();

        let meta = decode_tx(tx.tx_ack());
        assert_eq!(meta.version, Some(2));
        assert_eq!(meta.lock_time, Some(123));
        assert_eq!(meta.inputs_cnt, Some(1));
        assert_eq!(meta.outputs_cnt, Some(1));
        assert_eq!(meta.extra_data_len, Some(4));
        assert_eq!(meta.timestamp, Some(42));
        assert_eq!(meta.version_group_id, Some(7));
        assert_eq!(meta.expiry, Some(9));
        assert_eq!(meta.branch_id, Some(11));
        assert!(meta.extra_data.is_none());

        let input = decode_tx(tx.inputs[0].tx_ack());
        assert_eq!(input.inputs.len(), 1);
        assert_eq!(input.inputs[0].prev_hash, vec![0x33; 32]);
        assert_eq!(input.inputs[0].prev_index, 1);
        assert_eq!(input.inputs[0].script_sig, Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(input.inputs[0].sequence, Some(0xffff_fffd));
        assert!(input.inputs[0].script_type.is_none());

        let output = decode_tx(tx.bin_outputs[0].tx_ack());
        assert_eq!(output.bin_outputs[0].amount, 123);
        assert_eq!(output.bin_outputs[0].script_pubkey, vec![0x51, 0x21]);
        assert!(output.outputs.is_empty());

        let extra = decode_tx([0xaa, 0xbb, 0xcc][..].tx_ack());
        assert_eq!(extra.extra_data, Some(vec![0xaa, 0xbb, 0xcc]));
    }

    #[test]
    fn encodes_input_with_multisig_pubkeys() {
        let input = BtcSignInput {
            path: vec![0x8000_0030, 0x8000_0000, 0x8000_0000, 0x8000_0002, 0, 0],
            prev_hash: vec![0x11; 32],
            prev_index: 0,
            amount: 100_000,
            sequence: 0xffff_ffff,
            script_type: BtcInputScriptType::SpendMultisig,
            multisig: Some(BtcMultisig {
                pubkeys: vec![
                    BtcHDNodePath {
                        node: node(0xDEAD_BEEF, 0x02),
                        address_n: vec![0, 0],
                    },
                    BtcHDNodePath {
                        node: node(0x1234_5678, 0x03),
                        address_n: vec![0, 0],
                    },
                ],
                signatures: vec![vec![], vec![]],
                m: 2,
                nodes: Vec::new(),
                address_n: Vec::new(),
                pubkeys_order: BtcMultisigPubkeysOrder::Lexicographic,
            }),
            script_sig: None,
            witness: None,
            orig_hash: None,
            orig_index: None,
        };

        let tx = decode_tx(input.tx_ack());
        let tx_input = &tx.inputs[0];
        assert_eq!(
            tx_input.script_type,
            Some(BitcoinInputScriptTypeProto::SpendMultisig as i32)
        );
        assert_eq!(tx_input.amount, Some(100_000));

        let multisig = tx_input.multisig.as_ref().unwrap();
        assert_eq!(multisig.m, 2);
        assert_eq!(multisig.signatures, vec![Vec::<u8>::new(), Vec::new()]);
        assert_eq!(
            multisig.pubkeys_order,
            Some(MultisigPubkeysOrderProto::Lexicographic as i32)
        );
        assert_eq!(multisig.pubkeys.len(), 2);
        assert_eq!(multisig.pubkeys[0].node.depth, 4);
        assert_eq!(multisig.pubkeys[0].node.fingerprint, 0xDEAD_BEEF);
        assert_eq!(multisig.pubkeys[0].node.chain_code, vec![0x02; 32]);
        assert_eq!(multisig.pubkeys[0].node.public_key, vec![0x02; 33]);
        assert_eq!(multisig.pubkeys[0].node.private_key, None);
        assert_eq!(multisig.pubkeys[0].address_n, vec![0, 0]);
    }

    #[test]
    fn encodes_output_with_multisig_nodes_and_payment_request_index() {
        let output = BtcSignOutput {
            address: None,
            path: vec![0x8000_0030, 0x8000_0000, 0x8000_0000, 0x8000_0002, 1, 0],
            amount: 9_000,
            script_type: BtcOutputScriptType::PayToMultisig,
            multisig: Some(BtcMultisig {
                pubkeys: Vec::new(),
                signatures: vec![vec![], vec![], vec![]],
                m: 2,
                nodes: vec![
                    node(0xDEAD_BEEF, 0x02),
                    node(0x1234_5678, 0x03),
                    node(0x8765_4321, 0x04),
                ],
                address_n: vec![1, 0],
                pubkeys_order: BtcMultisigPubkeysOrder::Preserved,
            }),
            op_return_data: None,
            orig_hash: None,
            orig_index: None,
            payment_req_index: Some(0),
        };

        let tx = decode_tx(output.tx_ack());
        let tx_output = &tx.outputs[0];
        assert_eq!(
            tx_output.script_type,
            Some(BitcoinOutputScriptTypeProto::PayToMultisig as i32)
        );
        assert_eq!(tx_output.payment_req_index, Some(0));

        let multisig = tx_output.multisig.as_ref().unwrap();
        assert_eq!(multisig.m, 2);
        assert_eq!(multisig.address_n, vec![1, 0]);
        assert_eq!(
            multisig.pubkeys_order,
            Some(MultisigPubkeysOrderProto::Preserved as i32)
        );
        assert!(multisig.pubkeys.is_empty());
        let fingerprints: Vec<u32> = multisig.nodes.iter().map(|node| node.fingerprint).collect();
        assert_eq!(fingerprints, vec![0xDEAD_BEEF, 0x1234_5678, 0x8765_4321]);
    }
}
