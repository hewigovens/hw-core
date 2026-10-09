use anyhow::Result;
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::chain::Chain;

pub(super) struct MessagePath {
    pub(super) text: String,
    pub(super) indices: Vec<u32>,
}

impl MessagePath {
    // Unlike ResolvedDerivationPath, an explicit path is not checked against the chain.
    pub(super) fn resolve(chain: Chain, path: Option<&str>) -> Result<Self> {
        let text = path.unwrap_or(chain.default_path()).to_string();
        let indices = parse_bip32_path(&text)?;
        Ok(Self { text, indices })
    }
}
