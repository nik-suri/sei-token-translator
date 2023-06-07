use std::marker::PhantomData;

use cosmwasm_std::{
    testing::{mock_dependencies, mock_env, MockQuerier, MockStorage, MOCK_CONTRACT_ADDR},
    Addr, Api, Binary, CanonicalAddr, Empty, OwnedDeps, RecoverPubkeyError, StdError, StdResult,
    VerificationError, Coin,
};

use crate::state::CW_DENOMS;

use super::{contract_addr_from_base58, contract_addr_to_base58, parse_bank_token_factory_contract};

pub const SEI_CONTRACT_ADDR: &str =
    "sei1yw4wv2zqg9xkn67zvq3azye0t8h0x9kgyg3d53jym24gxt49vdyswk5upj";
pub const SEI_USER_ADDR: &str = "sei1vhkm2qv784rulx8ylru0zpvyvw3m3cy9x3xyfv";
pub const SEI_CONTRACT_ADDR_BYTES: [u8; 32] = [
    0x23, 0xaa, 0xe6, 0x28, 0x40, 0x41, 0x4d, 0x69, 0xeb, 0xc2, 0x60, 0x23, 0xd1, 0x13, 0x2f, 0x59,
    0xee, 0xf3, 0x16, 0xc8, 0x22, 0x22, 0xda, 0x46, 0x44, 0xda, 0xaa, 0x83, 0x2e, 0xa5, 0x63, 0x49,
];
pub const SEI_USER_ADDR_BYTES: [u8; 20] = [
    0x65, 0xed, 0xb5, 0x01, 0x9e, 0x3d, 0x47, 0xcf, 0x98, 0xe4, 0xf8, 0xf8, 0xf1, 0x05, 0x84, 0x63,
    0xa3, 0xb8, 0xe0, 0x85,
];

// Custom API mock implementation for testing.
// The custom impl helps us with correct addr_validate, addr_canonicalize, and addr_humanize methods for Sei.
#[derive(Clone)]
pub struct CustomApi {
    contract_addr: String,
    user_addr: String,
    contract_addr_bin: Binary,
    user_addr_bin: Binary,
}

impl CustomApi {
    pub fn new(
        contract_addr: &str,
        user_addr: &str,
        contract_addr_bytes: [u8; 32],
        user_addr_bytes: [u8; 20],
    ) -> Self {
        CustomApi {
            contract_addr: contract_addr.to_string(),
            user_addr: user_addr.to_string(),
            contract_addr_bin: Binary::from(contract_addr_bytes),
            user_addr_bin: Binary::from(user_addr_bytes),
        }
    }
}

impl Api for CustomApi {
    fn addr_validate(&self, input: &str) -> StdResult<Addr> {
        if input == self.contract_addr {
            return Ok(Addr::unchecked(self.contract_addr.clone()));
        }

        if input == self.user_addr {
            return Ok(Addr::unchecked(self.user_addr.clone()));
        }

        return Err(StdError::GenericErr {
            msg: "case not found".to_string(),
        });
    }

    fn addr_canonicalize(&self, input: &str) -> StdResult<CanonicalAddr> {
        if input == self.contract_addr {
            return Ok(CanonicalAddr(self.contract_addr_bin.clone()));
        }

        if input == self.user_addr {
            return Ok(CanonicalAddr(self.user_addr_bin.clone()));
        }

        return Err(StdError::GenericErr {
            msg: "case not found".to_string(),
        });
    }

    fn addr_humanize(&self, canonical: &CanonicalAddr) -> StdResult<Addr> {
        if *canonical == self.contract_addr_bin {
            return Ok(Addr::unchecked(self.contract_addr.clone()));
        }

        if *canonical == self.user_addr_bin {
            return Ok(Addr::unchecked(self.user_addr.clone()));
        }

        return Err(StdError::GenericErr {
            msg: "case not found".to_string(),
        });
    }

    fn secp256k1_verify(
        &self,
        message_hash: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, VerificationError> {
        Ok(cosmwasm_crypto::secp256k1_verify(
            message_hash,
            signature,
            public_key,
        )?)
    }

    fn secp256k1_recover_pubkey(
        &self,
        message_hash: &[u8],
        signature: &[u8],
        recovery_param: u8,
    ) -> Result<Vec<u8>, RecoverPubkeyError> {
        let pubkey =
            cosmwasm_crypto::secp256k1_recover_pubkey(message_hash, signature, recovery_param)?;
        Ok(pubkey.to_vec())
    }

    fn ed25519_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, VerificationError> {
        Ok(cosmwasm_crypto::ed25519_verify(
            message, signature, public_key,
        )?)
    }

    fn ed25519_batch_verify(
        &self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
        public_keys: &[&[u8]],
    ) -> Result<bool, VerificationError> {
        Ok(cosmwasm_crypto::ed25519_batch_verify(
            messages,
            signatures,
            public_keys,
        )?)
    }

    fn debug(&self, message: &str) {
        println!("{}", message);
    }
}

fn default_custom_mock_deps() -> OwnedDeps<MockStorage, CustomApi, MockQuerier, Empty> {
    custom_mock_deps(
        SEI_CONTRACT_ADDR,
        SEI_USER_ADDR,
        SEI_CONTRACT_ADDR_BYTES,
        SEI_USER_ADDR_BYTES,
    )
}

fn custom_mock_deps(
    contract_addr: &str,
    user_addr: &str,
    contract_addr_bytes: [u8; 32],
    user_addr_bytes: [u8; 20],
) -> OwnedDeps<MockStorage, CustomApi, MockQuerier, Empty> {
    OwnedDeps {
        storage: MockStorage::default(),
        api: CustomApi::new(
            contract_addr,
            user_addr,
            contract_addr_bytes,
            user_addr_bytes,
        ),
        querier: MockQuerier::default(),
        custom_query_type: PhantomData,
    }
}

// methods to test:
//
// instantiate
// migrate
//
// EXECUTE METHODS:
// execute
// complete_transfer_and_convert
// convert_and_transfer
// convert_bank_to_cw20
// handle_receiver_msg
// convert_cw20_to_bank
//
// REPLY METHODS:
// reply
// handle_complete_transfer_reply
//
// HELPER METHODS:
// parse_bank_token_factory_contract
// contract_addr_to_base58
// contract_addr_from_base58

// TESTS: instantiate
// 1. Happy path, ensure everything is set

// TESTS: migrate
// 1. Happy path, nothing should happen

// TESTS: execute
// 1. Ensure each message calls the correct method

// TESTS: complete_transfer_and_convert
// 1. Happy path
// 2. Failure: no token bridge address in state
// 3. Failure: couldn't serialize token bridge execute msg
// 4. Failure: couldn't serialize token bridge query msg
// 5. Failure: token bridge query TransferInfo failed
// 6. Failure: could not humanize recipient address
// 7. Failure: recipient address doesn't match contract address
// 8. Failure: couldn't save current transfer to storage

// TESTS: convert_and_transfer
// 1. Happy path
// 2. Failure: no token bridge address in state
// 3. Failure: no coin in funds
// 4. Failure: more coins than expected in funds
// 5. Failure: parse_bank_token_factory_contract method failure
// 6. Failure: couldn't serialize IncreaseAllowance msg
// 7. Failure: couldn't serialize InitiateTransfer msg

// TESTS: convert_bank_to_cw20
// 1. Happy path
// 2. Failure: no coin in funds
// 3. Failure: more coins than expected in funds
// 4. Failure: parse_bank_token_factory_contract method failure
// 5. Failure: couldn't serialize cw20::Transfer msg

// TESTS: handle_receiver_msg
// 1. Happy path
// 2. Failure: couldn't parse receive action payload

// TESTS: convert_cw20_to_bank
// 1. Happy path
// 2. Happy path + CreateDenom on TokenFactory
// 3. Failure: couldn't validate recipient address
// 4. Failure: couldn't validate contract address
// 5. Failure: contract_addr_to_base58 method failure
// 6. Failure: couldn't save contract addr => tokenfactory mapping to storage

// TESTS: reply
// 1. Happy path: REPLY ID matches
// 2. ID does not match reply -- no op

// TESTS: handle_complete_transfer_reply
// 1. Happy path: calls convert_cw20_to_bank
// 2. Failure: msg result is not okay
// 3. Failure: could not parse reply response_data
// 4. Failure: no data in the parsed response
// 5. Failure: could not deserialize response data
// 6. Failure: no contract in the response
// 7. Failure: no current transfer in storage
// 8. Failure: could not deserialize payload3 payload from stored transfer
// 9. Failure: could not convert the recipient base64 encoded bytes to a utf8 string

// TESTS: parse_bank_token_factory_contract
// 1. Happy path
#[test]
fn parse_bank_token_factory_contract_happy_path() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();

    let tokenfactory_denom = format!("factory/{}/{}", MOCK_CONTRACT_ADDR, "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa");
    let coin = Coin::new(100, tokenfactory_denom.clone());
    CW_DENOMS.save(deps.as_mut().storage, SEI_CONTRACT_ADDR.to_string(), &tokenfactory_denom).unwrap();

    let contract_addr = parse_bank_token_factory_contract(deps.as_mut(), env, coin).unwrap();
    assert_eq!(contract_addr, SEI_CONTRACT_ADDR);
}

// 2. Failure: parsed denom not of length 3
#[test]
fn parse_bank_token_factory_contract_failure_denom_length() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let coin = Coin::new(100, "tokenfactory/denom");

    let method_err = parse_bank_token_factory_contract(deps.as_mut(), env, coin).unwrap_err();
    assert_eq!(method_err.to_string(), "coin is not from the token factory");
}

// 3. Failure: parsed denom[0] != "factory"
#[test]
fn parse_bank_token_factory_contract_failure_non_factory_token() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let coin = Coin::new(100, "tokenfactory/contract/denom");

    let method_err = parse_bank_token_factory_contract(deps.as_mut(), env, coin).unwrap_err();
    assert_eq!(method_err.to_string(), "coin is not from the token factory");
}

// 4. Failure: parsed denom[1] != contract address
#[test]
fn parse_bank_token_factory_contract_failure_non_contract_created() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let coin = Coin::new(100, "factory/contract/denom");

    let method_err = parse_bank_token_factory_contract(deps.as_mut(), env, coin).unwrap_err();
    assert_eq!(method_err.to_string(), "coin is not from the token factory");
}

// 5. Failure: contract_addr_from_base58 method failure
#[test]
fn parse_bank_token_factory_contract_failure_base58_decode_failure() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let coin = Coin::new(100, format!("factory/{}/denom0", MOCK_CONTRACT_ADDR));

    let method_err = parse_bank_token_factory_contract(deps.as_mut(), env, coin).unwrap_err();
    assert_eq!(method_err.to_string(), "failed to decode base58 subdenom denom0");
}

// 6. Failure: the parsed contract address is not in CW_DENOMS storage
#[test]
fn parse_bank_token_factory_contract_failure_no_storage() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let coin = Coin::new(100, format!("factory/{}/{}", MOCK_CONTRACT_ADDR, "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa"));

    let method_err = parse_bank_token_factory_contract(deps.as_mut(), env, coin).unwrap_err();
    assert_eq!(method_err.to_string(), "a corresponding denom for the extracted contract addr is not contained in storage");
}

// 7. Failure: the stored denom doesn't equal the coin's denom
#[test]
fn parse_bank_token_factory_contract_failure_storage_mismatch() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let coin = Coin::new(100, format!("factory/{}/{}", MOCK_CONTRACT_ADDR, "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa"));

    CW_DENOMS.save(deps.as_mut().storage, SEI_CONTRACT_ADDR.to_string(), &"factory/fake/fake".to_string()).unwrap();

    let method_err = parse_bank_token_factory_contract(deps.as_mut(), env, coin).unwrap_err();
    assert_eq!(method_err.to_string(), "the stored denom for the contract does not match the actual coin denom");
}

// TESTS: contract_addr_to_base58
// 1. Happy path: convert to base58
#[test]
fn contract_addr_to_base58_happy_path() {
    let deps = default_custom_mock_deps();
    let b58_str = contract_addr_to_base58(
        deps.as_ref(),
        "sei1yw4wv2zqg9xkn67zvq3azye0t8h0x9kgyg3d53jym24gxt49vdyswk5upj".to_string(),
    ).unwrap();
    assert_eq!(b58_str, "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa");
}

// TESTS: contract_addr_from_base58
// 1. Happy path: convert to contract address
#[test]
fn contract_addr_from_base58_happy_path() {
    let deps = default_custom_mock_deps();
    let contract_addr = contract_addr_from_base58(
        deps.as_ref(),
        "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa",
    ).unwrap();
    assert_eq!(contract_addr, "sei1yw4wv2zqg9xkn67zvq3azye0t8h0x9kgyg3d53jym24gxt49vdyswk5upj");
}

// 2. Failure: could not decode base58
#[test]
fn contract_addr_from_base58_failure_decode_base58() {
    let deps = default_custom_mock_deps();
    let method_err = contract_addr_from_base58(
        deps.as_ref(),
        "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETD0",
    ).unwrap_err();
    assert_eq!(method_err.to_string(), "failed to decode base58 subdenom 3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETD0")
}