//! Build-time integrity check for the vendored wordlists (PRD §13.5.1, §13.5.5).
//!
//! The detector ships the ten official BIP39 wordlists as `wordlists/bip39/*.txt`
//! and the SLIP-0039 wordlist as `wordlists/slip0039/wordlist.txt`, matching
//! pasted tokens against them to identify mnemonics and Shamir shares. A wordlist
//! that was silently corrupted or swapped would weaken detection, so the SHA256
//! of each file is pinned here and re-verified on every build: a mismatch fails
//! the build with a clear message rather than shipping a tampered list.
//!
//! The pinned BIP39 digests are the canonical `bitcoin/bips/bip-0039/*.txt`
//! hashes (e.g. english.txt = 2f5eed53…dbda), which is also exactly what the
//! `bip39` crate uses for checksum validation — so prefix detection and checksum
//! validation can never drift apart. The SLIP-0039 digest is the canonical
//! `satoshilabs/slips/slip-0039/wordlist.txt` hash; its byte-correct word *order*
//! is independently confirmed by the RS1024 checksum tests in `slip39.rs` (a
//! single misplaced word would change the 10-bit indices and break those vectors).

use std::env;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

/// `(filename, expected lowercase-hex SHA256)` for each vendored BIP39 wordlist.
const BIP39_WORDLISTS: &[(&str, &str)] = &[
    (
        "english.txt",
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
    ),
    (
        "japanese.txt",
        "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd",
    ),
    (
        "korean.txt",
        "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60",
    ),
    (
        "spanish.txt",
        "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b",
    ),
    (
        "chinese_simplified.txt",
        "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726",
    ),
    (
        "chinese_traditional.txt",
        "417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f",
    ),
    (
        "french.txt",
        "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59",
    ),
    (
        "italian.txt",
        "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2",
    ),
    (
        "czech.txt",
        "7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc",
    ),
    (
        "portuguese.txt",
        "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f",
    ),
];

/// The single SLIP-0039 wordlist (`relative_path`, expected lowercase-hex
/// SHA256). 1024 words, the source of the 10-bit indices `slip39.rs` checks.
const SLIP0039_WORDLIST: (&str, &str) = (
    "wordlists/slip0039/wordlist.txt",
    "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3",
);

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    let base = Path::new(&manifest_dir);

    for (filename, expected) in BIP39_WORDLISTS {
        verify(base, &format!("wordlists/bip39/{filename}"), expected);
    }
    let (rel, expected) = SLIP0039_WORDLIST;
    verify(base, rel, expected);
}

/// Recompute the SHA256 of the wordlist at `manifest_dir/rel` and fail the build
/// if it does not match `expected`. Registers a `rerun-if-changed` so an edit
/// re-triggers the check.
fn verify(manifest_dir: &Path, rel: &str, expected: &str) {
    println!("cargo:rerun-if-changed={rel}");
    let path = manifest_dir.join(rel);

    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("wordlist {} is missing or unreadable: {e}", path.display()));

    let digest = Sha256::digest(bytes);
    let mut actual = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(actual, "{byte:02x}").expect("writing to a String never fails");
    }

    assert!(
        actual == *expected,
        "wordlist integrity check failed for {}\n  expected SHA256: {expected}\n  actual SHA256:   {actual}\nThe vendored wordlist was modified. Restore it from its canonical source (bitcoin/bips/bip-0039 or satoshilabs/slips/slip-0039) or update the pin if this change is intentional.",
        path.display()
    );
}
