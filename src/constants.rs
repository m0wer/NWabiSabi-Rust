/// Number of credentials issued/presented per request
pub const CREDENTIAL_NUMBER: usize = 2;

/// WabiSabi protocol identifier used in transcripts
pub const WABISABI_PROTOCOL_IDENTIFIER: &str = "WabiSabi_v1.0";

/// Domain separator for Strobe protocol
pub const DOMAIN_STROBE_SEPARATOR: &str = "domain-separator";

/// Maximum credential amount (100 million satoshis = 1 BTC)
pub const MAX_AMOUNT: u64 = 100_000_000;

/// Range proof width in bits (ceil(log2(MAX_AMOUNT)))
pub const RANGE_PROOF_WIDTH: usize = 27;
