use crate::{WalletError, WalletResult};
use bitcoin::{
    Address, CompressedPublicKey, Network, PublicKey,
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub},
    secp256k1::Secp256k1,
};
use ledger_bitcoin_client::{WalletPolicy, wallet::Version};
use ledger_connect::{ApduTransport, LedgerClient};

pub(super) struct BitcoinAccount {
    pub path: Vec<u32>,
    pub network: Network,
    pub fingerprint: Fingerprint,
    pub xpub: Xpub,
    pub policy: WalletPolicy,
}

impl BitcoinAccount {
    pub fn validate_path(path: &[u32]) -> WalletResult<Network> {
        if path.len() != 5
            || ![44, 49, 84, 86]
                .iter()
                .any(|purpose| path[0] == (purpose | 0x8000_0000))
            || ![0x8000_0000, 0x8000_0001].contains(&path[1])
            || path[2] < 0x8000_0000
            || path[3] > 1
            || path[4] >= 0x8000_0000
        {
            return Err(WalletError::Signing(
                "Ledger Bitcoin requires m/44'|49'|84'|86'/0'|1'/account'/0|1/index".into(),
            ));
        }
        Ok(if path[1] == 0x8000_0000 {
            Network::Bitcoin
        } else {
            Network::Testnet
        })
    }

    pub async fn load<T: ApduTransport + Send>(
        client: &mut LedgerClient<T>,
        path: &[u32],
    ) -> WalletResult<Self> {
        let network = Self::validate_path(path)?;
        let testnet = network != Network::Bitcoin;
        let account = Self::derivation(&path[..3]);
        let fingerprint = client.bitcoin_master_fingerprint(testnet).await?;
        let xpub = client.bitcoin_extended_pubkey(&account, testnet).await?;
        if xpub.depth != 3
            || xpub.child_number != ChildNumber::from(path[2])
            || xpub.network != network.into()
        {
            return Err(WalletError::Signing(
                "Ledger returned an unexpected Bitcoin account key".into(),
            ));
        }
        let descriptor = match path[0] & 0x7fff_ffff {
            44 => "pkh(@0/**)",
            49 => "sh(wpkh(@0/**))",
            84 => "wpkh(@0/**)",
            86 => "tr(@0/**)",
            _ => unreachable!("validated purpose"),
        };
        let policy = WalletPolicy::new(
            String::new(),
            Version::V2,
            descriptor.into(),
            [((fingerprint, account), xpub)],
        );
        Ok(Self {
            path: path[..3].to_vec(),
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
            .map_err(|_| WalletError::Signing("cannot derive Bitcoin account child".into()))?;
        Ok(PublicKey::new(child.public_key))
    }

    pub fn address(&self, path: &[u32]) -> WalletResult<Address> {
        let key = self.key(path)?;
        let compressed = CompressedPublicKey(key.inner);
        Ok(match path[0] & 0x7fff_ffff {
            44 => Address::p2pkh(key, self.network),
            49 => Address::p2shwpkh(&compressed, self.network),
            84 => Address::p2wpkh(&compressed, self.network),
            86 => Address::p2tr(
                &Secp256k1::verification_only(),
                key.inner.x_only_public_key().0,
                None,
                self.network,
            ),
            _ => unreachable!("validated purpose"),
        })
    }
}
