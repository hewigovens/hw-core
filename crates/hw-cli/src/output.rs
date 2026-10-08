use anyhow::Result;
use hw_wallet::chain::Chain;
use hw_wallet::message::{NormalizedMessageSignature, SignTypedDataResponseExt};
use trezor_connect::thp::{
    EthTxSignature, GetAddressResponse, SignMessageResponse, SignTypedDataResponse,
};

pub fn print_requesting(label: &str) {
    println!("Requesting {label} from device...");
}

pub fn print_labeled_value(label: &str, value: impl std::fmt::Display) {
    println!("{label}: {value}");
}

pub fn print_hex_field(label: &str, bytes: &[u8]) {
    println!("{label}: 0x{}", hex::encode(bytes));
}

fn print_message_signature(address: &str, normalized_signature: &str, raw_signature: &[u8]) {
    print_labeled_value("Address", address);
    print_labeled_value("Signature", normalized_signature);
    print_hex_field("Signature (hex)", raw_signature);
}

pub trait PrintResponse {
    fn print(&self) -> Result<()>;
}

impl PrintResponse for GetAddressResponse {
    fn print(&self) -> Result<()> {
        print_labeled_value("Address", &self.address);
        if let Some(mac) = &self.mac {
            println!("MAC: {}", hex::encode(mac));
        }
        if let Some(public_key) = &self.public_key {
            print_labeled_value("Public key", public_key);
        }
        Ok(())
    }
}

impl PrintResponse for SignMessageResponse {
    fn print(&self) -> Result<()> {
        if self.chain != Chain::Solana {
            let normalized = NormalizedMessageSignature::from(self);
            print_message_signature(&self.address, &normalized.value, &self.signature);
            return Ok(());
        }
        if !self.address.is_empty() {
            print_labeled_value("Address", &self.address);
        }
        print_hex_field("Signature (hex)", &self.signature);
        if let Some(signed_data) = &self.signed_data {
            print_hex_field("Signed data (hex)", signed_data);
        }
        Ok(())
    }
}

impl PrintResponse for SignTypedDataResponse {
    fn print(&self) -> Result<()> {
        let normalized = self.formatted_signature()?;
        print_message_signature(&self.address, &normalized, &self.signature);
        Ok(())
    }
}

impl PrintResponse for EthTxSignature {
    fn print(&self) -> Result<()> {
        print_labeled_value("v", self.v);
        print_hex_field("r", &self.r);
        print_hex_field("s", &self.s);
        Ok(())
    }
}
