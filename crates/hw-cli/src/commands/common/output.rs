use hw_wallet::eth::VerifiedSignature;
use trezor_connect::thp::SignTxResponse;

pub fn print_requesting(label: &str) {
    println!("Requesting {label} from device...");
}

pub fn print_labeled_value(label: &str, value: impl std::fmt::Display) {
    println!("{label}: {value}");
}

pub fn print_hex_field(label: &str, bytes: &[u8]) {
    println!("{label}: 0x{}", hex::encode(bytes));
}

pub fn print_address_response(address: &str, mac: Option<&[u8]>, public_key: Option<&str>) {
    print_labeled_value("Address", address);
    if let Some(mac) = mac {
        println!("MAC: {}", hex::encode(mac));
    }
    if let Some(public_key) = public_key {
        print_labeled_value("Public key", public_key);
    }
}

pub fn print_message_signature_response(
    address: &str,
    normalized_signature: &str,
    raw_signature: &[u8],
) {
    print_labeled_value("Address", address);
    print_labeled_value("Signature", normalized_signature);
    print_hex_field("Signature (hex)", raw_signature);
}

pub fn print_eth_sign_tx_response(
    response: &SignTxResponse,
    verification: Option<&VerifiedSignature>,
) {
    print_labeled_value("v", response.v);
    print_hex_field("r", &response.r);
    print_hex_field("s", &response.s);
    if let Some(verification) = verification {
        print_hex_field("tx_hash", &verification.tx_hash);
        print_labeled_value("recovered_address", &verification.recovered_address);
    }
}
