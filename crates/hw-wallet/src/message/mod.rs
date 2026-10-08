mod sign_message;
mod signature;
mod typed_data;

#[cfg(test)]
mod tests;

pub use sign_message::SignMessageRequestExt;
pub use signature::{NormalizedMessageSignature, SignatureEncoding};
pub use typed_data::{SignTypedDataRequestExt, SignTypedDataResponseExt};
