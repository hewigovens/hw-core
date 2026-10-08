mod backend;
mod bitcoin;
mod channel;
mod credentials;
mod errors;
mod link;
mod nfc;
mod pairing;
mod signing;
mod thp_backend;

pub use backend::BleBackend;

#[cfg(test)]
mod tests;
