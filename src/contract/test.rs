use std::marker::PhantomData;

use cosmwasm_std::{
    coin,
    testing::{
        mock_dependencies, mock_env, mock_info, MockQuerier, MockStorage, MOCK_CONTRACT_ADDR,
    },
    to_binary, Addr, Api, BankMsg, Binary, CanonicalAddr, Coin, ContractResult, CosmosMsg, Empty,
    Env, OwnedDeps, RecoverPubkeyError, ReplyOn, StdError, StdResult, SystemError, SystemResult,
    VerificationError, WasmMsg, WasmQuery,
};
use cw_token_bridge::msg::TransferInfoResponse;
use sei_cosmwasm::SeiMsg;

use crate::{
    contract::{complete_transfer_and_convert, COMPLETE_TRANSFER_REPLY_ID},
    state::{CW_DENOMS, TOKEN_BRIDGE_CONTRACT, CURRENT_TRANSFER, WORMHOLE_CONTRACT}, msg::InstantiateMsg,
};

use super::{
    contract_addr_from_base58, contract_addr_to_base58, convert_and_transfer, convert_bank_to_cw20,
    convert_cw20_to_bank, handle_receiver_msg, parse_bank_token_factory_contract, instantiate,
};

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

fn mock_env_custom_contract(contract_addr: impl Into<String>) -> Env {
    let mut env = mock_env();
    env.contract.address = Addr::unchecked(contract_addr);
    return env;
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
#[test]
fn instantiate_happy_path() {
    let tokenbridge_addr = "faketokenbridge".to_string();
    let corebridge_addr = "fakewormhole".to_string();

    let mut deps = mock_dependencies();
    let env = mock_env();
    let info = mock_info(SEI_USER_ADDR, &vec![]);
    let msg = InstantiateMsg {
        token_bridge_contract: tokenbridge_addr.clone(),
        wormhole_contract: corebridge_addr.clone(),
    };

    let response = instantiate(deps.as_mut(), env, info, msg).unwrap();

    // response should have 2 attributes
    assert_eq!(response.attributes.len(), 2);
    assert_eq!(response.attributes[0].key, "action");
    assert_eq!(response.attributes[0].value, "instantiate");
    assert_eq!(response.attributes[1].key, "owner");
    assert_eq!(response.attributes[1].value, SEI_USER_ADDR);

    // contract addrs should have been set in storage
    let saved_tb = TOKEN_BRIDGE_CONTRACT.load(deps.as_mut().storage).unwrap();
    assert_eq!(saved_tb, tokenbridge_addr);

    let saved_wh = WORMHOLE_CONTRACT.load(deps.as_mut().storage).unwrap();
    assert_eq!(saved_wh, corebridge_addr);
}

// TESTS: complete_transfer_and_convert
// 1. Happy path
#[test]
fn complete_transfer_and_convert_happy_path() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env_custom_contract(SEI_CONTRACT_ADDR);

    let transfer_info_response = cw_token_bridge::msg::TransferInfoResponse {
        amount: 1000000u32.into(),
        token_address: hex::decode("0000000000000000000000009c3c9283d3e44854697cd22d3faa240cfb032889").unwrap().try_into().unwrap(),
        token_chain: 5,
        recipient: hex::decode("23aae62840414d69ebc26023d1132f59eef316c82222da4644daaa832ea56349").unwrap().try_into().unwrap(),
        recipient_chain: 32,
        fee: 0u32.into(),
        payload: hex::decode("7b2262617369635f726563697069656e74223a7b22726563697069656e74223a22633256704d575636637a56745a4731334f486436646d4e7a4f585a344f586b335a4774306357646c4d336c36626a52334d477735626a5130227d7d").unwrap(),
    };
    let transfer_info_response_copy = transfer_info_response.clone();

    deps.querier.update_wasm(move |q| match q {
        WasmQuery::Smart {
            contract_addr: _,
            msg: _,
        } => SystemResult::Ok(ContractResult::Ok(to_binary(&transfer_info_response_copy).unwrap())),
        _ => SystemResult::Err(SystemError::UnsupportedRequest {
            kind: "wasm".to_string(),
        }),
    });

    let token_bridge_addr = "faketokenbridge".to_string();
    TOKEN_BRIDGE_CONTRACT
        .save(deps.as_mut().storage, &token_bridge_addr)
        .unwrap();

    let info = mock_info(SEI_USER_ADDR, &vec![]);
    let vaa = Binary::from_base64("AAAAAA").unwrap();

    let response = complete_transfer_and_convert(deps.as_mut(), env, info, vaa).unwrap();

    // response should have 1 message
    assert_eq!(response.messages.len(), 1);

    // 1. WasmMsg::Execute (token bridge complete transfer)
    assert_eq!(response.messages[0].id, COMPLETE_TRANSFER_REPLY_ID);
    assert_eq!(response.messages[0].reply_on, ReplyOn::Success);
    assert_eq!(
        response.messages[0].msg,
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: token_bridge_addr,
            msg: Binary::from_base64("eyJjb21wbGV0ZV90cmFuc2Zlcl93aXRoX3BheWxvYWQiOnsiZGF0YSI6IkFBQUFBQT09IiwicmVsYXllciI6InNlaTF2aGttMnF2Nzg0cnVseDh5bHJ1MHpwdnl2dzNtM2N5OXgzeHlmdiJ9fQ==").unwrap(),
            funds: vec![]
        })
    );

    // response should have 2 attributes
    assert_eq!(response.attributes.len(), 2);
    assert_eq!(response.attributes[0].key, "action");
    assert_eq!(response.attributes[0].value, "complete_transfer_with_payload");
    assert_eq!(response.attributes[1].key, "transfer_payload");
    assert_eq!(response.attributes[1].value, Binary::from(transfer_info_response.clone().payload).to_base64());

    // finally, validate that the state was saved into storage
    let saved_transfer = CURRENT_TRANSFER.load(deps.as_mut().storage).unwrap();
    assert_eq!(saved_transfer, transfer_info_response);
}

// 2. Failure: no token bridge address in state
#[test]
fn complete_transfer_and_convert_no_token_bridge_state() {
    let mut deps = default_custom_mock_deps();
    let info = mock_info(SEI_USER_ADDR, &vec![]);
    let env = mock_env();
    let vaa = Binary::from_base64("fakevaa").unwrap();

    let err = complete_transfer_and_convert(deps.as_mut(), env, info, vaa).unwrap_err();
    assert_eq!(
        err.to_string(),
        "could not load token bridge contract address"
    );
}

// 3. Failure: token bridge query TransferInfo failed
#[test]
fn complete_transfer_and_convert_failure_transferinfo_query() {
    let mut deps = default_custom_mock_deps();
    deps.querier.update_wasm(|q| match q {
        WasmQuery::Smart {
            contract_addr: _,
            msg: _,
        } => SystemResult::Ok(ContractResult::Err("query failed".to_string())),
        _ => SystemResult::Err(SystemError::UnsupportedRequest {
            kind: "wasm".to_string(),
        }),
    });

    let token_bridge_addr = "faketokenbridge".to_string();
    TOKEN_BRIDGE_CONTRACT
        .save(deps.as_mut().storage, &token_bridge_addr)
        .unwrap();

    let info = mock_info(SEI_USER_ADDR, &vec![]);
    let env = mock_env();
    let vaa = Binary::from_base64("fakevaa").unwrap();

    let err = complete_transfer_and_convert(deps.as_mut(), env, info, vaa).unwrap_err();
    assert_eq!(err.to_string(), "could not parse token bridge payload3 vaa");
}

// 4. Failure: could not humanize recipient address
#[test]
fn complete_transfer_and_convert_failure_humanize_recipient() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();

    let transfer_info_response = to_binary(&cw_token_bridge::msg::TransferInfoResponse {
        amount: 1000000u32.into(),
        token_address: hex::decode("0000000000000000000000009c3c9283d3e44854697cd22d3faa240cfb032889").unwrap().try_into().unwrap(),
        token_chain: 5,
        recipient: hex::decode("6d9ae6b2d333c1d65301a59da3eed388ca5dc60cb12496584b75cbe6b15fdbed").unwrap().try_into().unwrap(),
        recipient_chain: 32,
        fee: 0u32.into(),
        payload: hex::decode("7b2262617369635f726563697069656e74223a7b22726563697069656e74223a22633256704d575636637a56745a4731334f486436646d4e7a4f585a344f586b335a4774306357646c4d336c36626a52334d477735626a5130227d7d").unwrap(),
    }).unwrap();

    deps.querier.update_wasm(move |q| match q {
        WasmQuery::Smart {
            contract_addr: _,
            msg: _,
        } => SystemResult::Ok(ContractResult::Ok(transfer_info_response.clone())),
        _ => SystemResult::Err(SystemError::UnsupportedRequest {
            kind: "wasm".to_string(),
        }),
    });

    let token_bridge_addr = "faketokenbridge".to_string();
    TOKEN_BRIDGE_CONTRACT
        .save(deps.as_mut().storage, &token_bridge_addr)
        .unwrap();

    let info = mock_info(SEI_USER_ADDR, &vec![]);
    let vaa = Binary::from_base64("AAAAAA").unwrap();

    let err = complete_transfer_and_convert(deps.as_mut(), env, info, vaa).unwrap_err();
    assert_eq!(err.to_string(), "Generic error: case not found");
}

// 5. Failure: recipient address doesn't match contract address
#[test]
fn complete_transfer_and_convert_nomatch_recipient_contract() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();

    let transfer_info_response = to_binary(&cw_token_bridge::msg::TransferInfoResponse {
        amount: 1000000u32.into(),
        token_address: hex::decode("0000000000000000000000009c3c9283d3e44854697cd22d3faa240cfb032889").unwrap().try_into().unwrap(),
        token_chain: 5,
        recipient: hex::decode("23aae62840414d69ebc26023d1132f59eef316c82222da4644daaa832ea56349").unwrap().try_into().unwrap(),
        recipient_chain: 32,
        fee: 0u32.into(),
        payload: hex::decode("7b2262617369635f726563697069656e74223a7b22726563697069656e74223a22633256704d575636637a56745a4731334f486436646d4e7a4f585a344f586b335a4774306357646c4d336c36626a52334d477735626a5130227d7d").unwrap(),
    }).unwrap();

    deps.querier.update_wasm(move |q| match q {
        WasmQuery::Smart {
            contract_addr: _,
            msg: _,
        } => SystemResult::Ok(ContractResult::Ok(transfer_info_response.clone())),
        _ => SystemResult::Err(SystemError::UnsupportedRequest {
            kind: "wasm".to_string(),
        }),
    });

    let token_bridge_addr = "faketokenbridge".to_string();
    TOKEN_BRIDGE_CONTRACT
        .save(deps.as_mut().storage, &token_bridge_addr)
        .unwrap();

    let info = mock_info(SEI_USER_ADDR, &vec![]);
    let vaa = Binary::from_base64("AAAAAA").unwrap();

    let err = complete_transfer_and_convert(deps.as_mut(), env, info, vaa).unwrap_err();
    assert_eq!(err.to_string(), "vaa recipient must be this contract");
}

// TESTS: convert_and_transfer
// 1. Happy path
#[test]
fn convert_and_transfer_happy_path() {
    let mut deps = default_custom_mock_deps();

    let token_bridge_addr = "faketokenbridge".to_string();
    TOKEN_BRIDGE_CONTRACT
        .save(deps.as_mut().storage, &token_bridge_addr)
        .unwrap();
    let tokenfactory_denom =
        "factory/cosmos2contract/3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa".to_string();
    CW_DENOMS
        .save(
            deps.as_mut().storage,
            SEI_CONTRACT_ADDR.to_string(),
            &tokenfactory_denom,
        )
        .unwrap();
    let coin = coin(1, tokenfactory_denom);

    let info = mock_info(SEI_USER_ADDR, &vec![coin.clone()]);
    let env = mock_env();
    let recipient_chain = 2;
    let recipient = Binary::from_base64("AAAAAAAAAAAAAAAAjyagAl3Mxs/Aen04dWKAoQ4pWtc=").unwrap();
    let fee = 0u32;

    let response = convert_and_transfer(
        deps.as_mut(),
        info,
        env,
        recipient_chain,
        recipient,
        fee.into(),
    )
    .unwrap();

    // response should have 3 messages
    assert_eq!(response.messages.len(), 3);

    // 1. SeiMsg::BurnTokens
    assert_eq!(
        response.messages[0].msg,
        CosmosMsg::Custom(SeiMsg::BurnTokens {
            amount: coin.clone()
        })
    );

    // 2. WasmMsg::Execute (increase allowance)
    assert_eq!(
        response.messages[1].msg,
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: SEI_CONTRACT_ADDR.to_string(),
            msg: Binary::from_base64("eyJpbmNyZWFzZV9hbGxvd2FuY2UiOnsic3BlbmRlciI6ImZha2V0b2tlbmJyaWRnZSIsImFtb3VudCI6IjEiLCJleHBpcmVzIjpudWxsfX0=").unwrap(),
            funds: vec![]
        })
    );

    // 3. WasmMsg::Execute (initiate transfer)
    assert_eq!(
        response.messages[2].msg,
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: token_bridge_addr,
            msg: Binary::from_base64("eyJpbml0aWF0ZV90cmFuc2ZlciI6eyJhc3NldCI6eyJpbmZvIjp7InRva2VuIjp7ImNvbnRyYWN0X2FkZHIiOiJzZWkxeXc0d3YyenFnOXhrbjY3enZxM2F6eWUwdDhoMHg5a2d5ZzNkNTNqeW0yNGd4dDQ5dmR5c3drNXVwaiJ9fSwiYW1vdW50IjoiMSJ9LCJyZWNpcGllbnRfY2hhaW4iOjIsInJlY2lwaWVudCI6IkFBQUFBQUFBQUFBQUFBQUFqeWFnQWwzTXhzL0FlbjA0ZFdLQW9RNHBXdGM9IiwiZmVlIjoiMCIsIm5vbmNlIjowfX0=").unwrap(),
            funds: vec![]
        })
    );
}

// 2. Failure: no token bridge address in state
#[test]
fn convert_and_transfer_no_token_bridge_state() {
    let mut deps = default_custom_mock_deps();
    let info = mock_info(SEI_USER_ADDR, &vec![]);
    let env = mock_env();
    let recipient_chain = 2;
    let recipient = Binary::from_base64("AAAAAAAAAAAAAAAAjyagAl3Mxs/Aen04dWKAoQ4pWtc=").unwrap();
    let fee = 0u32;

    let err = convert_and_transfer(
        deps.as_mut(),
        info,
        env,
        recipient_chain,
        recipient,
        fee.into(),
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "could not load token bridge contract address"
    );
}

// 3. Failure: no coin in funds
#[test]
fn convert_and_transfer_no_funds() {
    let mut deps = default_custom_mock_deps();

    let token_bridge_addr = "faketokenbridge".to_string();
    TOKEN_BRIDGE_CONTRACT
        .save(deps.as_mut().storage, &token_bridge_addr)
        .unwrap();

    let info = mock_info(SEI_USER_ADDR, &vec![]);
    let env = mock_env();
    let recipient_chain = 2;
    let recipient = Binary::from_base64("AAAAAAAAAAAAAAAAjyagAl3Mxs/Aen04dWKAoQ4pWtc=").unwrap();
    let fee = 0u32;

    let err = convert_and_transfer(
        deps.as_mut(),
        info,
        env,
        recipient_chain,
        recipient,
        fee.into(),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "info.funds should contain only 1 coin");
}

// 4. Failure: more coins than expected in funds
#[test]
fn convert_and_transfer_too_many_funds() {
    let mut deps = default_custom_mock_deps();

    let token_bridge_addr = "faketokenbridge".to_string();
    TOKEN_BRIDGE_CONTRACT
        .save(deps.as_mut().storage, &token_bridge_addr)
        .unwrap();

    let info = mock_info(SEI_USER_ADDR, &vec![coin(1, "denomA"), coin(1, "denomB")]);
    let env = mock_env();
    let recipient_chain = 2;
    let recipient = Binary::from_base64("AAAAAAAAAAAAAAAAjyagAl3Mxs/Aen04dWKAoQ4pWtc=").unwrap();
    let fee = 0u32;

    let err = convert_and_transfer(
        deps.as_mut(),
        info,
        env,
        recipient_chain,
        recipient,
        fee.into(),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "info.funds should contain only 1 coin");
}

// 5. Failure: parse_bank_token_factory_contract method failure
#[test]
fn convert_and_transfer_parse_method_failure() {
    let mut deps = default_custom_mock_deps();

    let token_bridge_addr = "faketokenbridge".to_string();
    TOKEN_BRIDGE_CONTRACT
        .save(deps.as_mut().storage, &token_bridge_addr)
        .unwrap();

    let info = mock_info(SEI_USER_ADDR, &vec![coin(1, "denomA")]);
    let env = mock_env();
    let recipient_chain = 2;
    let recipient = Binary::from_base64("AAAAAAAAAAAAAAAAjyagAl3Mxs/Aen04dWKAoQ4pWtc=").unwrap();
    let fee = 0u32;

    let err = convert_and_transfer(
        deps.as_mut(),
        info,
        env,
        recipient_chain,
        recipient,
        fee.into(),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "coin is not from the token factory");
}

// TESTS: convert_bank_to_cw20
// 1. Happy path
#[test]
fn convert_bank_to_cw20_happy_path() {
    let mut deps = default_custom_mock_deps();

    let tokenfactory_denom =
        "factory/cosmos2contract/3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa".to_string();
    CW_DENOMS
        .save(
            deps.as_mut().storage,
            SEI_CONTRACT_ADDR.to_string(),
            &tokenfactory_denom,
        )
        .unwrap();
    let coin = coin(1, tokenfactory_denom);
    let info = mock_info(SEI_USER_ADDR, &vec![coin.clone()]);
    let env = mock_env();

    let response = convert_bank_to_cw20(deps.as_mut(), info, env).unwrap();

    // response should have 2 messages
    assert_eq!(response.messages.len(), 2);

    // 1. SeiMsg::BurnTokens
    assert_eq!(
        response.messages[0].msg,
        CosmosMsg::Custom(SeiMsg::BurnTokens {
            amount: coin.clone()
        })
    );

    // 2. WasmMsg::Execute
    assert_eq!(
        response.messages[1].msg,
        CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: SEI_CONTRACT_ADDR.to_string(),
            msg: Binary::from_base64("eyJ0cmFuc2ZlciI6eyJyZWNpcGllbnQiOiJzZWkxdmhrbTJxdjc4NHJ1bHg4eWxydTB6cHZ5dnczbTNjeTl4M3h5ZnYiLCJhbW91bnQiOiIxIn19").unwrap(),
            funds: vec![]
        })
    )
}

// 2. Failure: no coin in funds
#[test]
fn convert_bank_to_cw20_failure_no_funds() {
    let mut deps = default_custom_mock_deps();
    let info = mock_info(SEI_USER_ADDR, &vec![]);
    let env = mock_env();

    let err = convert_bank_to_cw20(deps.as_mut(), info, env).unwrap_err();
    assert_eq!(err.to_string(), "info.funds should contain only 1 coin");
}

// 3. Failure: more coins than expected in funds
#[test]
fn convert_bank_to_cw20_failure_too_many_funds() {
    let mut deps = default_custom_mock_deps();
    let info = mock_info(SEI_USER_ADDR, &vec![coin(1, "denomA"), coin(1, "denomB")]);
    let env = mock_env();

    let err = convert_bank_to_cw20(deps.as_mut(), info, env).unwrap_err();
    assert_eq!(err.to_string(), "info.funds should contain only 1 coin");
}

// 4. Failure: parse_bank_token_factory_contract method failure
#[test]
fn convert_bank_to_cw20_failure_invalid_token() {
    let mut deps = default_custom_mock_deps();
    let info = mock_info(SEI_USER_ADDR, &vec![coin(1, "denomA")]);
    let env = mock_env();

    let err = convert_bank_to_cw20(deps.as_mut(), info, env).unwrap_err();
    assert_eq!(err.to_string(), "coin is not from the token factory");
}

// TESTS: handle_receiver_msg
// 1. Happy path
#[test]
fn handle_receiver_msg_happy_path() {
    let mut deps = default_custom_mock_deps();
    let info = mock_info(SEI_CONTRACT_ADDR, &vec![]);
    let env = mock_env();
    let sender = SEI_USER_ADDR.to_string();
    let amount = 1u32;
    let msg_payload = Binary::from_base64("eyJjb252ZXJ0X3RvX2JhbmsiOnt9fQ==").unwrap();

    let response =
        handle_receiver_msg(deps.as_mut(), info, env, sender, amount.into(), msg_payload).unwrap();
    assert_eq!(response.messages.len(), 3);
}

// 2. Failure: couldn't parse receive action payload
#[test]
fn handle_receiver_msg_invalid_payload() {
    let mut deps = default_custom_mock_deps();
    let info = mock_info(SEI_CONTRACT_ADDR, &vec![]);
    let env = mock_env();
    let sender = SEI_USER_ADDR.to_string();
    let amount = 1u32;
    let msg_payload = Binary::from_base64("Jjb252ZXJ0X3RvX2JhbmsiOnt9fQ").unwrap();

    let err = handle_receiver_msg(deps.as_mut(), info, env, sender, amount.into(), msg_payload)
        .unwrap_err();
    assert_eq!(err.to_string(), "could not parse receive action payload");
}

// TESTS: convert_cw20_to_bank
// 1. Happy path
#[test]
fn convert_cw20_to_bank_happy_path() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let recipient = SEI_USER_ADDR.to_string();
    let amount = 1;
    let contract_addr = SEI_CONTRACT_ADDR.to_string();

    let tokenfactory_denom =
        "factory/cosmos2contract/3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa".to_string();
    CW_DENOMS
        .save(
            deps.as_mut().storage,
            contract_addr.clone(),
            &tokenfactory_denom,
        )
        .unwrap();

    let response = convert_cw20_to_bank(
        deps.as_mut(),
        env,
        recipient.clone(),
        amount.clone(),
        contract_addr,
    )
    .unwrap();

    // response should have 2 messages:
    assert_eq!(response.messages.len(), 2);

    // 1. SeiMsg::MintTokens
    let expected_coin = coin(amount, tokenfactory_denom);
    assert_eq!(
        response.messages[0].msg,
        CosmosMsg::Custom(SeiMsg::MintTokens {
            amount: expected_coin.clone()
        })
    );

    // 2. BankMsg::Send
    assert_eq!(
        response.messages[1].msg,
        CosmosMsg::Bank(BankMsg::Send {
            to_address: recipient,
            amount: vec![expected_coin]
        })
    );
}

// 2. Happy path + CreateDenom on TokenFactory
#[test]
fn convert_cw20_to_bank_happy_path_create_denom() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let recipient = SEI_USER_ADDR.to_string();
    let amount = 1;
    let contract_addr = SEI_CONTRACT_ADDR.to_string();

    let tokenfactory_denom =
        "factory/cosmos2contract/3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa".to_string();

    let response = convert_cw20_to_bank(
        deps.as_mut(),
        env,
        recipient.clone(),
        amount.clone(),
        contract_addr,
    )
    .unwrap();

    // response should have 3 messages:
    assert_eq!(response.messages.len(), 3);

    // 1. SeiMsg::CreateDenom
    assert_eq!(
        response.messages[0].msg,
        CosmosMsg::Custom(SeiMsg::CreateDenom {
            subdenom: "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa".to_string()
        })
    );

    // 2. SeiMsg::MintTokens
    let expected_coin = coin(amount, tokenfactory_denom);
    assert_eq!(
        response.messages[1].msg,
        CosmosMsg::Custom(SeiMsg::MintTokens {
            amount: expected_coin.clone()
        })
    );

    // 3. BankMsg::Send
    assert_eq!(
        response.messages[2].msg,
        CosmosMsg::Bank(BankMsg::Send {
            to_address: recipient,
            amount: vec![expected_coin]
        })
    );
}

// 3. Failure: couldn't validate recipient address
#[test]
fn convert_cw20_to_bank_failure_invalid_recipient() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let recipient = "badSeiAddress".to_string();
    let amount = 1;
    let contract_addr = "badContractAddr".to_string();

    let method_err =
        convert_cw20_to_bank(deps.as_mut(), env, recipient, amount, contract_addr).unwrap_err();
    assert_eq!(
        method_err.to_string(),
        "invalid recipient address badSeiAddress"
    );
}

// 4. Failure: couldn't validate contract address
#[test]
fn convert_cw20_to_bank_failure_invalid_contract() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let recipient = SEI_USER_ADDR.to_string();
    let amount = 1;
    let contract_addr = "badContractAddr".to_string();

    let method_err =
        convert_cw20_to_bank(deps.as_mut(), env, recipient, amount, contract_addr).unwrap_err();
    assert_eq!(
        method_err.to_string(),
        "invalid contract address badContractAddr"
    );
}

// match &response.messages[2].msg {
//     CosmosMsg::Wasm(msg) => {
//         match msg {
//             WasmMsg::Execute { contract_addr, msg, funds } => println!("this is initiate transfer: {}", msg),
//             _ => println!("no inner match")
//         }
//     },
//     _ => println!("no match")
// }

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

    let tokenfactory_denom = format!(
        "factory/{}/{}",
        MOCK_CONTRACT_ADDR, "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa"
    );
    let coin = Coin::new(100, tokenfactory_denom.clone());
    CW_DENOMS
        .save(
            deps.as_mut().storage,
            SEI_CONTRACT_ADDR.to_string(),
            &tokenfactory_denom,
        )
        .unwrap();

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
    assert_eq!(
        method_err.to_string(),
        "failed to decode base58 subdenom denom0"
    );
}

// 6. Failure: the parsed contract address is not in CW_DENOMS storage
#[test]
fn parse_bank_token_factory_contract_failure_no_storage() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let coin = Coin::new(
        100,
        format!(
            "factory/{}/{}",
            MOCK_CONTRACT_ADDR, "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa"
        ),
    );

    let method_err = parse_bank_token_factory_contract(deps.as_mut(), env, coin).unwrap_err();
    assert_eq!(
        method_err.to_string(),
        "a corresponding denom for the extracted contract addr is not contained in storage"
    );
}

// 7. Failure: the stored denom doesn't equal the coin's denom
#[test]
fn parse_bank_token_factory_contract_failure_storage_mismatch() {
    let mut deps = default_custom_mock_deps();
    let env = mock_env();
    let coin = Coin::new(
        100,
        format!(
            "factory/{}/{}",
            MOCK_CONTRACT_ADDR, "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETDa"
        ),
    );

    CW_DENOMS
        .save(
            deps.as_mut().storage,
            SEI_CONTRACT_ADDR.to_string(),
            &"factory/fake/fake".to_string(),
        )
        .unwrap();

    let method_err = parse_bank_token_factory_contract(deps.as_mut(), env, coin).unwrap_err();
    assert_eq!(
        method_err.to_string(),
        "the stored denom for the contract does not match the actual coin denom"
    );
}

// TESTS: contract_addr_to_base58
// 1. Happy path: convert to base58
#[test]
fn contract_addr_to_base58_happy_path() {
    let deps = default_custom_mock_deps();
    let b58_str = contract_addr_to_base58(
        deps.as_ref(),
        "sei1yw4wv2zqg9xkn67zvq3azye0t8h0x9kgyg3d53jym24gxt49vdyswk5upj".to_string(),
    )
    .unwrap();
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
    )
    .unwrap();
    assert_eq!(
        contract_addr,
        "sei1yw4wv2zqg9xkn67zvq3azye0t8h0x9kgyg3d53jym24gxt49vdyswk5upj"
    );
}

// 2. Failure: could not decode base58
#[test]
fn contract_addr_from_base58_failure_decode_base58() {
    let deps = default_custom_mock_deps();
    let method_err = contract_addr_from_base58(
        deps.as_ref(),
        "3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETD0",
    )
    .unwrap_err();
    assert_eq!(
        method_err.to_string(),
        "failed to decode base58 subdenom 3QEQyi7iyJHwQ4wfUMLFPB4kRzczMAXCitWh7h6TETD0"
    )
}
