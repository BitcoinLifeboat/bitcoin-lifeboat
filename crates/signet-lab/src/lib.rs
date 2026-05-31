//! Disposable regtest and Signet wallets for practice drills.
//!
//! This crate is intentionally isolated from the core audit/reporting workspace:
//! it is the only place that depends on `bdk_wallet`, matching the v0.2 boundary
//! in PRD §3.2 and §11.1. Wallets are created in memory with
//! `create_wallet_no_persist()`, so no descriptor, key, address index, or UTXO
//! state is written to disk by this layer.

pub mod regtest;

use std::fmt;
use std::str::FromStr;

pub use bdk_wallet::bitcoin;
use bdk_wallet::KeychainKind;
pub use bdk_wallet::{SignOptions, Wallet};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
pub use bitcoin::Network;
use error_taxonomy::{ErrorCode, LifeboatError};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

/// A deterministic, non-mainnet seed used for tests and the default practice
/// wallet. It is not a real user secret and must never be used for funds.
pub const DEFAULT_PRACTICE_SEED: [u8; 32] = [0x42; 32];

const ACCOUNT_PATH: &str = "m/84'/1'/0'";
const ACCOUNT_PATH_DISPLAY: &str = "84h/1h/0h";

/// The networks supported by the disposable practice-wallet lab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PracticeNetwork {
    /// Offline regtest rehearsal. This is Practice Mode's default network.
    Regtest,
    /// Public Signet rehearsal. Later stories add explicit user consent before
    /// any network call; this crate only builds local wallets and addresses.
    Signet,
}

impl PracticeNetwork {
    /// The rust-bitcoin network value used by BDK address derivation.
    #[must_use]
    pub const fn network(self) -> Network {
        match self {
            Self::Regtest => Network::Regtest,
            Self::Signet => Network::Signet,
        }
    }

    /// Stable snake_case display string for UI/JSON boundaries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Signet => "signet",
        }
    }
}

impl fmt::Display for PracticeNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A derived practice-wallet address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PracticeAddress {
    keychain: PracticeKeychain,
    index: u32,
    address: String,
}

impl PracticeAddress {
    /// Receive or change chain.
    #[must_use]
    pub const fn keychain(&self) -> PracticeKeychain {
        self.keychain
    }

    /// BIP32 child index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Human-readable Bitcoin address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// Receive/change address chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PracticeKeychain {
    /// External receive addresses.
    Receive,
    /// Internal change addresses.
    Change,
}

impl PracticeKeychain {
    const fn bdk_keychain(self) -> KeychainKind {
        match self {
            Self::Receive => KeychainKind::External,
            Self::Change => KeychainKind::Internal,
        }
    }

    /// Stable snake_case display string for UI/JSON boundaries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::Change => "change",
        }
    }
}

impl fmt::Display for PracticeKeychain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An in-memory BDK wallet suitable only for disposable practice drills.
pub struct DisposableWallet {
    network: PracticeNetwork,
    wallet: Wallet,
    external_descriptor: String,
    internal_descriptor: String,
}

impl DisposableWallet {
    /// Generate a fresh disposable practice wallet from OS randomness.
    pub fn new(network: PracticeNetwork) -> Result<Self, LifeboatError> {
        Self::generate(network)
    }

    /// Generate a fresh disposable practice wallet from OS randomness.
    pub fn generate(network: PracticeNetwork) -> Result<Self, LifeboatError> {
        let mut seed = [0_u8; 32];
        OsRng.try_fill_bytes(&mut seed).map_err(|_| {
            LifeboatError::new(ErrorCode::Internal)
                .with_context("failed to read OS randomness for practice wallet")
        })?;
        let wallet = Self::from_seed(network, &seed);
        seed.zeroize();
        wallet
    }

    /// Create the deterministic default practice wallet for a network.
    pub fn from_default_practice_seed(network: PracticeNetwork) -> Result<Self, LifeboatError> {
        Self::from_seed(network, &DEFAULT_PRACTICE_SEED)
    }

    /// Create a deterministic disposable wallet from caller-provided seed bytes.
    ///
    /// BIP32 accepts 16..=64 bytes. The seed is used only to construct an
    /// in-memory BDK wallet; this crate does not persist it or log it.
    pub fn from_seed(network: PracticeNetwork, seed: &[u8]) -> Result<Self, LifeboatError> {
        if !(16..=64).contains(&seed.len()) {
            return Err(LifeboatError::new(ErrorCode::InputInvalidFormat)
                .with_context("practice wallet seed must be 16..=64 bytes"));
        }

        let (external_descriptor, internal_descriptor) = descriptors_from_seed(seed)?;
        let wallet = Wallet::create(external_descriptor.clone(), internal_descriptor.clone())
            .network(network.network())
            .create_wallet_no_persist()
            .map_err(|_| {
                LifeboatError::new(ErrorCode::Internal)
                    .with_context("failed to create disposable practice wallet")
            })?;

        Ok(Self {
            network,
            wallet,
            external_descriptor,
            internal_descriptor,
        })
    }

    /// The practice network this wallet derives for.
    #[must_use]
    pub const fn practice_network(&self) -> PracticeNetwork {
        self.network
    }

    /// The rust-bitcoin network this wallet derives for.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network.network()
    }

    /// Borrow the underlying in-memory BDK wallet for later PSBT drill stories.
    #[must_use]
    pub const fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// Mutably borrow the underlying in-memory BDK wallet for local drill steps.
    ///
    /// This is intended for detached drill crates such as `psbt-drill` that need
    /// to update the in-memory wallet graph or stage BDK PSBT operations. Callers
    /// must keep the no-persistence/no-logging guarantees of this crate.
    #[must_use]
    pub const fn wallet_mut(&mut self) -> &mut Wallet {
        &mut self.wallet
    }

    /// External descriptor used to create receive addresses.
    ///
    /// This descriptor contains the disposable practice xprv, so callers must
    /// treat it as secret and avoid displaying or logging it.
    #[must_use]
    pub fn external_descriptor(&self) -> &str {
        &self.external_descriptor
    }

    /// Internal descriptor used to create change addresses.
    ///
    /// This descriptor contains the disposable practice xprv, so callers must
    /// treat it as secret and avoid displaying or logging it.
    #[must_use]
    pub fn internal_descriptor(&self) -> &str {
        &self.internal_descriptor
    }

    /// Peek a receive address without revealing or persisting the BDK index.
    #[must_use]
    pub fn receive_address(&self, index: u32) -> PracticeAddress {
        self.address(PracticeKeychain::Receive, index)
    }

    /// Peek a change address without revealing or persisting the BDK index.
    #[must_use]
    pub fn change_address(&self, index: u32) -> PracticeAddress {
        self.address(PracticeKeychain::Change, index)
    }

    /// Peek an address without revealing or persisting the BDK index.
    #[must_use]
    pub fn address(&self, keychain: PracticeKeychain, index: u32) -> PracticeAddress {
        let info = self.wallet.peek_address(keychain.bdk_keychain(), index);
        PracticeAddress {
            keychain,
            index: info.index,
            address: info.address.to_string(),
        }
    }
}

fn descriptors_from_seed(seed: &[u8]) -> Result<(String, String), LifeboatError> {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Testnet, seed).map_err(|_| {
        LifeboatError::new(ErrorCode::InputInvalidFormat)
            .with_context("practice wallet seed must be valid BIP32 entropy")
    })?;
    let fingerprint = master.fingerprint(&secp);
    let account_path = DerivationPath::from_str(ACCOUNT_PATH).map_err(|_| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("practice wallet account path is invalid")
    })?;
    let account_xpriv = master.derive_priv(&secp, &account_path).map_err(|_| {
        LifeboatError::new(ErrorCode::Internal)
            .with_context("failed to derive practice wallet account key")
    })?;

    Ok((
        descriptor(&fingerprint.to_string(), &account_xpriv.to_string(), 0),
        descriptor(&fingerprint.to_string(), &account_xpriv.to_string(), 1),
    ))
}

fn descriptor(fingerprint: &str, account_xpriv: &str, branch: u8) -> String {
    format!("wpkh([{fingerprint}/{ACCOUNT_PATH_DISPLAY}]{account_xpriv}/{branch}/*)")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &[u8; 32] = b"lifeboat deterministic seed test";

    #[test]
    fn creates_deterministic_regtest_wallet() {
        let first = DisposableWallet::from_seed(PracticeNetwork::Regtest, TEST_SEED)
            .expect("regtest wallet");
        let second = DisposableWallet::from_seed(PracticeNetwork::Regtest, TEST_SEED)
            .expect("regtest wallet");

        let first_receive = first.receive_address(0);
        let second_receive = second.receive_address(0);
        let change = first.change_address(0);

        assert_eq!(first.practice_network(), PracticeNetwork::Regtest);
        assert_eq!(first.network(), Network::Regtest);
        assert_eq!(first_receive, second_receive);
        assert_ne!(first_receive.address(), change.address());
        assert!(first_receive.address().starts_with("bcrt1"));
        assert_eq!(first_receive.keychain(), PracticeKeychain::Receive);
        assert_eq!(first_receive.index(), 0);
    }

    #[test]
    fn creates_deterministic_signet_wallet() {
        let first =
            DisposableWallet::from_seed(PracticeNetwork::Signet, TEST_SEED).expect("signet wallet");
        let second =
            DisposableWallet::from_seed(PracticeNetwork::Signet, TEST_SEED).expect("signet wallet");

        let first_receive = first.receive_address(0);
        let second_receive = second.receive_address(0);

        assert_eq!(first.practice_network(), PracticeNetwork::Signet);
        assert_eq!(first.network(), Network::Signet);
        assert_eq!(first_receive, second_receive);
        assert!(first_receive.address().starts_with("tb1"));
    }

    #[test]
    fn generated_wallet_derives_addresses() {
        let wallet = DisposableWallet::generate(PracticeNetwork::Regtest)
            .expect("generated practice wallet");

        assert!(wallet.receive_address(0).address().starts_with("bcrt1"));
        assert_ne!(
            wallet.receive_address(0).address(),
            wallet.change_address(0).address()
        );
    }

    #[test]
    fn default_practice_seed_is_deterministic() {
        let via_default = DisposableWallet::from_default_practice_seed(PracticeNetwork::Regtest)
            .expect("default wallet");
        let via_seed =
            DisposableWallet::from_seed(PracticeNetwork::Regtest, &DEFAULT_PRACTICE_SEED)
                .expect("seeded wallet");

        assert_eq!(
            via_default.receive_address(7).address(),
            via_seed.receive_address(7).address()
        );
    }

    #[test]
    fn rejects_seed_lengths_bip32_cannot_use() {
        let err = match DisposableWallet::from_seed(PracticeNetwork::Regtest, &[0x42; 15]) {
            Ok(_) => panic!("short seed must be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.code(), ErrorCode::InputInvalidFormat);
    }

    #[test]
    fn descriptors_are_kept_available_for_later_drill_steps() {
        let wallet =
            DisposableWallet::from_seed(PracticeNetwork::Signet, TEST_SEED).expect("signet wallet");

        assert!(wallet.external_descriptor().starts_with("wpkh(["));
        assert!(wallet.external_descriptor().contains("/0/*)"));
        assert!(wallet.internal_descriptor().contains("/1/*)"));
        assert_ne!(wallet.external_descriptor(), wallet.internal_descriptor());
    }
}
