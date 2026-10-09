use hw_wallet::eip712::normalize_typed_data_signature;
use hw_wallet::eth::verify_sign_tx_response;
use hw_wallet::message::{
    SignatureEncoding as WalletSignatureEncoding, normalize_message_signature,
};
use trezor_connect::thp::{SignTxRequest as ThpSignTxRequest, ThpWorkflow};

use super::request_mapping::{
    map_get_address_request, map_sign_message_request, map_sign_tx_request,
    map_sign_typed_data_request,
};
use crate::errors::HWCoreError;
use crate::types::{
    AddressResult, GetAddressRequest, SignMessageRequest, SignMessageResult, SignTxRequest,
    SignTxResult, SignTypedDataRequest, SignTypedDataResult, SignatureEncoding,
};

pub(crate) async fn get_address_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: GetAddressRequest,
) -> Result<AddressResult, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    let thp_request = map_get_address_request(request)?;
    let response = workflow
        .get_address(thp_request)
        .await
        .map_err(HWCoreError::from)?;
    Ok(AddressResult {
        chain: response.chain,
        address: response.address,
        mac: response.mac.map(|mac| format!("0x{}", hex::encode(mac))),
        public_key: response.public_key,
    })
}

pub(crate) async fn get_nonce_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
) -> Result<String, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    let nonce = workflow.get_nonce().await.map_err(HWCoreError::from)?;
    Ok(format!("0x{}", hex::encode(nonce)))
}

pub(crate) async fn sign_tx_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: SignTxRequest,
) -> Result<SignTxResult, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    let chain = request.chain;
    let sign_request = map_sign_tx_request(request)?;
    let response = workflow
        .sign_tx(sign_request.clone())
        .await
        .map_err(HWCoreError::from)?;
    let verification = match &sign_request {
        ThpSignTxRequest::Ethereum(tx) => verify_sign_tx_response(tx, &response).ok(),
        ThpSignTxRequest::Bitcoin(_) | ThpSignTxRequest::Solana(_) => None,
    };
    Ok(SignTxResult {
        chain,
        v: response.v,
        r: response.r,
        s: response.s,
        signatures: response.signatures,
        tx_hash: verification.as_ref().map(|sig| sig.tx_hash.to_vec()),
        recovered_address: verification.map(|sig| sig.recovered_address),
    })
}

fn map_signature_encoding(encoding: WalletSignatureEncoding) -> SignatureEncoding {
    match encoding {
        WalletSignatureEncoding::Hex => SignatureEncoding::Hex,
        WalletSignatureEncoding::Base64 => SignatureEncoding::Base64,
    }
}

pub(crate) async fn sign_message_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: SignMessageRequest,
) -> Result<SignMessageResult, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    let sign_request = map_sign_message_request(request)?;
    let response = workflow
        .sign_message(sign_request)
        .await
        .map_err(HWCoreError::from)?;
    let normalized = normalize_message_signature(&response).map_err(HWCoreError::from)?;
    Ok(SignMessageResult {
        chain: response.chain,
        address: response.address,
        signature: response.signature,
        signature_formatted: normalized.value,
        signature_encoding: map_signature_encoding(normalized.encoding),
        signed_data: response.signed_data,
    })
}

pub(crate) async fn sign_typed_data_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: SignTypedDataRequest,
) -> Result<SignTypedDataResult, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    let sign_request = map_sign_typed_data_request(request)?;
    let response = workflow
        .sign_typed_data(sign_request)
        .await
        .map_err(HWCoreError::from)?;
    let normalized = normalize_typed_data_signature(&response).map_err(HWCoreError::from)?;
    Ok(SignTypedDataResult {
        chain: response.chain,
        address: response.address,
        signature: response.signature,
        signature_formatted: normalized,
        signature_encoding: SignatureEncoding::Hex,
    })
}
