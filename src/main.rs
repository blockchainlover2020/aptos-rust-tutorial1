// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Error, Context, Result};
use aptos::common::utils;
use aptos_sdk::{
    coin_client::CoinClient,
    rest_client::{
      Client, FaucetClient,
      aptos_api_types::{U64, ViewRequest, EntryFunctionId}
    },
    types::LocalAccount,
    transaction_builder::TransactionBuilder,
    move_types::{
      ident_str,
      language_storage::{ModuleId, TypeTag},
    },
    crypto::{ed25519::{ Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, PublicKey}, ValidCryptoMaterialStringExt},
    transaction_builder::TransactionFactory,
    types::{
      account_address::AccountAddress,
      transaction::{
        EntryFunction, Script, SignedTransaction, TransactionArgument, TransactionPayload,
      }
    },
};

use once_cell::sync::Lazy;
use std::str::FromStr;
use url::Url;
use tiny_keccak::{Hasher, Sha3};
use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

pub mod serialize;
pub mod primitive_types;

use crate::primitive_types::{H256, H160};

// :!:>section_1c
static NODE_URL: Lazy<Url> = Lazy::new(|| {
    Url::from_str(
        std::env::var("APTOS_NODE_URL")
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("https://fullnode.devnet.aptoslabs.com"),
    )
    .unwrap()
});

static FAUCET_URL: Lazy<Url> = Lazy::new(|| {
    Url::from_str(
        std::env::var("APTOS_FAUCET_URL")
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("https://faucet.devnet.aptoslabs.com"),
    )
    .unwrap()
});
// <:!:section_1c

#[tokio::main]
async fn main() -> Result<()> {
    // :!:>section_1a
    let rest_client = Client::new(NODE_URL.clone());
    let faucet_client = FaucetClient::new(FAUCET_URL.clone(), NODE_URL.clone()); // <:!:section_1a

    // :!:>section_1b
    let coin_client = CoinClient::new(&rest_client); // <:!:section_1b

    // Create two accounts locally, Alice and Bob.
    // :!:>section_2
    let mut alice = LocalAccount::generate(&mut rand::rngs::OsRng);
    let bob = LocalAccount::generate(&mut rand::rngs::OsRng); // <:!:section_2

    // Print account addresses.
    println!("\n=== Addresses ===");
    println!("Alice: {}", alice.address().to_hex_literal());
    println!("Bob: {}", bob.address().to_hex_literal());

    // Create the accounts on chain, but only fund Alice.
    // :!:>section_3
    /*faucet_client
        .fund(alice.address(), 100_000_000)
        .await
        .context("Failed to fund Alice's account")?;
    faucet_client
        .create_account(bob.address())
        .await
        .context("Failed to fund Bob's account")?; // <:!:section_3

    // Print initial balances.
    println!("\n=== Initial Balances ===");
    println!(
        "Alice: {:?}",
        coin_client
            .get_account_balance(&alice.address())
            .await
            .context("Failed to get Alice's account balance")?
    );
    println!(
        "Bob: {:?}",
        coin_client
            .get_account_balance(&bob.address())
            .await
            .context("Failed to get Bob's account balance")?
    );

    // Have Alice send Bob some coins.
    let txn_hash = coin_client
        .transfer(&mut alice, bob.address(), 1_000, None)
        .await
        .context("Failed to submit transaction to transfer coins")?;
    rest_client
        .wait_for_transaction(&txn_hash)
        .await
        .context("Failed when waiting for the transfer transaction")?;

    // Print intermediate balances.
    println!("\n=== Intermediate Balances ===");
    // :!:>section_4
    println!(
        "Alice: {:?}",
        coin_client
            .get_account_balance(&alice.address())
            .await
            .context("Failed to get Alice's account balance the second time")?
    );
    println!(
        "Bob: {:?}",
        coin_client
            .get_account_balance(&bob.address())
            .await
            .context("Failed to get Bob's account balance the second time")?
    ); // <:!:section_4

    // Have Alice send Bob some more coins.
    // :!:>section_5
    let txn_hash = coin_client
        .transfer(&mut alice, bob.address(), 1_000, None)
        .await
        .context("Failed to submit transaction to transfer coins")?; // <:!:section_5
                                                                     // :!:>section_6
    rest_client
        .wait_for_transaction(&txn_hash)
        .await
        .context("Failed when waiting for the transfer transaction")?; // <:!:section_6

    // Print final balances.
    println!("\n=== Final Balances ===");
    println!(
        "Alice: {:?}",
        coin_client
            .get_account_balance(&alice.address())
            .await
            .context("Failed to get Alice's account balance the second time")?
    );
    println!(
        "Bob: {:?}",
        coin_client
            .get_account_balance(&bob.address())
            .await
            .context("Failed to get Bob's account balance the second time")?
    );
    */

    const GAS_LIMIT: u64 = 100000;
    let transaction_factory = TransactionFactory::new(utils::chain_id(&rest_client).await?)
    .with_gas_unit_price(100)
    .with_max_gas_amount(GAS_LIMIT);

    let contract_hex_literal_addy = "0x61ad49767d3dd5d5e6e41563c3ca3e8600c52c350ca66014ee7f6874f28f5ddb";
    let contract_address: AccountAddress = AccountAddress::from_hex_literal(contract_hex_literal_addy).unwrap();
    let try_call: bool = true;


    if try_call {
      let _entry = EntryFunction::new(
        ModuleId::new(
          contract_address,
          ident_str!("validator_announce").to_owned()
        ),
        ident_str!("announce").to_owned(),
        vec![],
        vec![
          bcs::to_bytes(&AccountAddress::from_hex_literal("0x4c327ccb881a7542be77500b2833dc84c839e7b7").unwrap()).unwrap(),
          bcs::to_bytes(&hex::decode("20ac937917284eaa3d67287278fc51875874241fffab5eb5fd8ae899a7074c5679be15f0bdb5b4f7594cefc5cba17df59b68ba3c55836053a23307db5a95610d1b").unwrap()).unwrap(),
          bcs::to_bytes(&"s3://hyperlane-mainnet2-ethereum-validator-0/us-east-1").unwrap()
        ]
      );

      let payload = TransactionPayload::EntryFunction(_entry);
      let signed_tx = alice.sign_with_transaction_builder(transaction_factory.payload(payload));
      let response = rest_client.submit_and_wait(&signed_tx).await?.into_inner();
      println!("response {:?}", signed_tx.committed_hash().to_hex_literal());
    }
    
    let resource_type = format!("{}::validator_announce::ValidatorState", contract_address.to_hex_literal());
    println!("resource_type {:?}", resource_type);

    let validator_state = rest_client.get_account_resource(
      contract_address, 
      resource_type.as_str()
    ).await
      .context("Error on getting account resource")?
      .into_inner()
      .context("No resource found")?;
  
    let data = serde_json::from_str::<ValidatorState>(
      &validator_state.data.to_string()
    ).context("Error on parsing ValidatorState Resource")?;

    
    println!("{:?}", data.storage_locations);

    let try_simulate = false;
    if try_simulate {
      let _entry = EntryFunction::new(
        ModuleId::new(
          contract_address,
          ident_str!("validator_announce").to_owned()
        ),
        ident_str!("get_announced_storage_locations").to_owned(),
        vec![],
        vec![
          bcs::to_bytes(&AccountAddress::from_hex_literal("0x4c327ccb881a7542be77500b2833dc84c839e7b7").unwrap()).unwrap(),
        ]
      );
      let payload = TransactionPayload::EntryFunction(_entry);

      let raw_tx = transaction_factory
        .payload(payload)
        .sender(alice.address())
        .sequence_number(alice.sequence_number())
        .build();
      let signed_tx = SignedTransaction::new(
        raw_tx,
        alice.public_key().clone(),
        Ed25519Signature::try_from([0u8; 64].as_ref()).unwrap()
      );

      let response_txns = 
        rest_client.simulate(&signed_tx).await?
        .into_inner();
      let response = response_txns
        .first()
        .unwrap();
      println!("simulate response {:?}", response);
      if !response.info.success {
        return Err(Error::msg("Simulation Failed"));
      }
    }

    let try_view = false;
    if try_view {
      let view_response = rest_client.view(
        &ViewRequest {
          function: EntryFunctionId::from_str(
            &format!("{}::validator_announce::get_announced_storage_locations", contract_address.to_hex_literal())
          ).unwrap(),
          type_arguments: vec![],
          arguments: vec![
            serde_json::Value::Array(
              vec![serde_json::Value::String("0x4c327ccb881a7542be77500b2833dc84c839e7b7".to_string())]
            ),
          ]
        },
        Option::None
      ).await?;

      let view_result = serde_json::from_str::<Vec<Vec<String>>>(&view_response.inner()[0].to_string());
      println!("view_result {:?}", view_result);
    }


    /*let address = // AccountAddress::from_bytes(vec![89, 130, 100, 255, 49, 241, 152, 246, 7, 18, 38, 178, 183, 233, 206, 54, 1, 99, 172, 205]).unwrap();
      AccountAddress::from_hex_literal("0x598264FF31f198f6071226b2B7e9ce360163aCcD").unwrap();
    println!("address {:?} {:?} {:?}", address.to_string(), 
        hex::encode(vec![89, 130, 100, 255, 49, 241, 152, 246, 7, 18, 38, 178, 183, 233, 206, 54, 1, 99, 172, 205]),
        AccountAddress::from_hex_literal(
          &format!("0x{}", hex::encode(vec![89, 130, 100, 255, 49, 241, 152, 246, 7, 18, 38, 178, 183, 233, 206, 54, 1, 99, 172, 205]))
        ).unwrap()
    );*/
    if try_view {
      
      let view_response = rest_client.view(
        &ViewRequest {
          function: EntryFunctionId::from_str(
            &format!(
              "{}::mailbox::outbox_get_tree", 
              "0x60fdd95a3d802f33a5e8623c50b1cdc4967c28bed42ba861e592f54786d186e3"
            )
          ).unwrap(),
          type_arguments: vec![],
          arguments: vec![]
        },
        Option::None
      )
      .await?;

      println!("view_response {:?}", view_response);

      let view_result = serde_json::from_str::<MoveMerkleTree>(&view_response.inner()[0].to_string()).unwrap();
      println!("{:?}", view_result);

    }
    Ok(())
}


/*
  struct ValidatorState has key, store {
    mailbox: address,
    domain: u32,
    storage_locations: SimpleMap<address, vector<String>>,
    replay_protection: vector<vector<u8>>,
    validators_list: vector<address>,
    // event handlers
    announcement_events: EventHandle<AnnouncementEvent>,
  }
*/
#[derive(Serialize, Deserialize, Debug)]
pub struct MoveMerkleTree {
  branch: Vec<String>,
  count: String
}

const TREE_DEPTH: usize = 32;

impl Into<IncrementalMerkle> for MoveMerkleTree {
  fn into(self) -> IncrementalMerkle {
    let mut branches: Vec<H256> = vec![];
    for branch in self.branch.iter() {
      branches.push(H256::from_str(branch).unwrap());
    }
    if branches.len() < 32 {
      while branches.len() < 32 { branches.push(H256::zero()); }
    }
    let count = self.count.parse::<usize>().unwrap();
    
    IncrementalMerkle {
      branch: branches[0..TREE_DEPTH].try_into().unwrap(),
      count
    }
  }
}

pub struct IncrementalMerkle {
  branch: [H256; TREE_DEPTH],
  count: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventHandle {
    pub counter: U64,
    pub guid: Guid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Guid {
    pub id: ID,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ID {
    pub addr: AccountAddress,
    pub creation_num: U64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Element {
  pub key: String,
  pub value: Vec<String>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SimpleMap {
  data: Vec<Element>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ValidatorState {
  mailbox: AccountAddress,
  domain: u32,
  storage_locations: SimpleMap,
  replay_protection: Vec<String>,//Vec<Vec<u8>>,
  validators_list: Vec<AccountAddress>, //Vec<AccountAddress>,
  announcement_events: EventHandle
}