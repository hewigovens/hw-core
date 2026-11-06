use super::bitcoin_purpose::BitcoinPurpose;
use crate::{WalletError, WalletResult, bip32::HARDENED};
use bitcoin::{
    Address, CompressedPublicKey, Network, PublicKey,
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
    secp256k1::Secp256k1,
};
use ledger_bitcoin_client::{WalletPolicy, wallet::Version};
use ledger_connect::{ApduTransport, LedgerClient};

pub(super) struct BitcoinAccount {
    pub path: Vec<u32>,
    pub purpose: BitcoinPurpose,
    pub network: Network,
    pub fingerprint: Fingerprint,
    pub xpub: Xpub,
    pub policy: WalletPolicy,
}

impl BitcoinAccount {
    pub fn validate_path(path: &[u32]) -> WalletResult<(BitcoinPurpose, Network)> {
        let invalid = || {
            WalletError::InvalidBip32Path(
                "Ledger Bitcoin requires m/44'|49'|84'|86'/0'|1'/account'/0|1/index".into(),
            )
        };
        let [purpose, coin, account, branch, index] = path else {
            return Err(invalid());
        };
        let purpose = BitcoinPurpose::from_component(*purpose).ok_or_else(invalid)?;
        if ![HARDENED, HARDENED | 1].contains(coin)
            || *account < HARDENED
            || *branch > 1
            || *index >= HARDENED
        {
            return Err(invalid());
        }
        Ok((
            purpose,
            if *coin == HARDENED {
                Network::Bitcoin
            } else {
                Network::Testnet
            },
        ))
    }

    pub async fn load<T: ApduTransport + Send>(
        client: &mut LedgerClient<T>,
        path: &[u32],
    ) -> WalletResult<Self> {
        let (purpose, network) = Self::validate_path(path)?;
        let testnet = network != Network::Bitcoin;
        let account = Self::derivation(&path[..3]);
        let fingerprint = client.bitcoin_master_fingerprint(testnet).await?;
        let xpub = client.bitcoin_extended_pubkey(&account, testnet).await?;
        if xpub.depth != 3
            || xpub.child_number != ChildNumber::from(path[2])
            || xpub.network != network.into()
        {
            return Err(WalletError::Verification(
                "Ledger returned an unexpected Bitcoin account key".into(),
            ));
        }
        let policy = WalletPolicy::new(
            String::new(),
            Version::V2,
            purpose.descriptor().into(),
            [((fingerprint, account), xpub)],
        );
        Ok(Self {
            path: path[..3].to_vec(),
            purpose,
            network,
            fingerprint,
            xpub,
            policy,
        })
    }

    pub fn derivation(path: &[u32]) -> DerivationPath {
        DerivationPath::from(
            path.iter()
                .copied()
                .map(ChildNumber::from)
                .collect::<Vec<_>>(),
        )
    }

    pub fn key(&self, path: &[u32]) -> WalletResult<PublicKey> {
        Self::validate_path(path)?;
        if path[..3] != self.path {
            return Err(WalletError::Signing(
                "Ledger Bitcoin transaction must use one account".into(),
            ));
        }
        let child = self
            .xpub
            .derive_pub(
                &Secp256k1::verification_only(),
                &Self::derivation(&path[3..]),
            )
            .map_err(|_| WalletError::Verification("cannot derive Bitcoin account child".into()))?;
        Ok(PublicKey::new(child.public_key))
    }

    pub fn address(&self, path: &[u32]) -> WalletResult<Address> {
        let key = self.key(path)?;
        let compressed = CompressedPublicKey(key.inner);
        Ok(match self.purpose {
            BitcoinPurpose::Legacy => Address::p2pkh(key, self.network),
            BitcoinPurpose::NestedSegwit => Address::p2shwpkh(&compressed, self.network),
            BitcoinPurpose::Segwit => Address::p2wpkh(&compressed, self.network),
            BitcoinPurpose::Taproot => Address::p2tr(
                &Secp256k1::verification_only(),
                key.inner.x_only_public_key().0,
                None,
                self.network,
            ),
        })
    }
}
