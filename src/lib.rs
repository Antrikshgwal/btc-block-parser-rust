mod base128;
mod block;
mod merkle;
mod transactions;
mod undo;
mod xor;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

use bitcoin::consensus::encode;
use block::analyze_blocks;
use transactions::{analyze_transaction, decode_transaction};

pub fn run_cli() -> Result<(), CliError> {
    let args = CliArgs::parse();
    let mode = Mode::try_from(args)?;

    match mode {
        Mode::Fixture { fixture } => handle_fixture_mode(fixture),
        Mode::Block { blk, rev, xor } => handle_block_mode(blk, rev, xor),
    }
}

pub fn emit_error(err: &CliError) {
    let payload = json!({
        "ok": false,
        "error": {
            "code": err.code(),
            "message": err.to_string(),
        }
    });

    println!("{}", payload);
}

fn handle_fixture_mode(fixture_path: PathBuf) -> Result<(), CliError> {
    let fixture = Fixture::from_file(&fixture_path)?;
    let tx = decode_transaction(&fixture.raw_tx)?;
    let report = analyze_transaction(&fixture, &tx)?;
    let txid = tx.compute_txid().to_string();

    write_report_to_out(&txid, &report)?;

    let pretty = serde_json::to_string_pretty(&report)?;
    println!("{}", pretty);

    Ok(())
}

fn handle_block_mode(blk: PathBuf, rev: PathBuf, xor: PathBuf) -> Result<(), CliError> {
    analyze_blocks(&blk, &rev, &xor)
}

#[derive(Parser, Debug)]
#[command(
    name = "chain-lens-cli",
    about = "Bitcoin transaction and block analyzer"
)]
struct CliArgs {
    #[arg(long = "block", value_names = ["BLK", "REV", "XOR"], num_args = 3)]
    block_files: Option<Vec<PathBuf>>,

    #[arg(value_name = "FIXTURE", required = false)]
    fixture: Option<PathBuf>,
}

enum Mode {
    Fixture {
        fixture: PathBuf,
    },
    Block {
        blk: PathBuf,
        rev: PathBuf,
        xor: PathBuf,
    },
}

impl TryFrom<CliArgs> for Mode {
    type Error = CliError;

    fn try_from(args: CliArgs) -> Result<Self, Self::Error> {
        match (args.block_files, args.fixture) {
            (Some(files), None) => {
                let mut iter = files.into_iter();
                let blk = iter.next().expect("clap enforces num_args");
                let rev = iter.next().expect("clap enforces num_args");
                let xor = iter.next().expect("clap enforces num_args");
                Ok(Mode::Block { blk, rev, xor })
            }
            (None, Some(fixture)) => Ok(Mode::Fixture { fixture }),
            (Some(_), Some(_)) => Err(CliError::InvalidArgs(
                "Cannot combine --block with a fixture path".into(),
            )),
            (None, None) => Err(CliError::InvalidArgs(
                "Fixture path missing; provide <fixture.json> or --block <blk> <rev> <xor>".into(),
            )),
        }
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    InvalidArgs(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Invalid hex: {0}")]
    InvalidHex(String),
    #[error("Transaction decode error: {0}")]
    TxDecode(#[from] encode::Error),
    #[error("Invalid transaction: {0}")]
    InvalidTx(String),
    #[error("Not implemented: {0}")]
    NotImplemented(&'static str),
}

impl CliError {
    fn code(&self) -> &'static str {
        match self {
            CliError::InvalidArgs(_) => "INVALID_ARGS",
            CliError::Io(_) => "IO_ERROR",
            CliError::Serde(_) => "SERDE_ERROR",
            CliError::InvalidHex(_) => "INVALID_HEX",
            CliError::TxDecode(_) => "TX_DECODE_ERROR",
            CliError::InvalidTx(_) => "INVALID_TX",
            CliError::NotImplemented(_) => "NOT_IMPLEMENTED",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Fixture {
    pub network: String,
    pub raw_tx: String,
    pub prevouts: Vec<Prevout>,
}

impl Fixture {
    pub fn from_file(path: &Path) -> Result<Self, CliError> {
        let raw = fs::read_to_string(path)?;
        let fixture: Fixture = serde_json::from_str(&raw)?;
        Ok(fixture)
    }
}

#[derive(Debug, Deserialize)]
pub struct Prevout {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
}

pub fn write_report_to_out<T: Serialize>(file_stem: &str, value: &T) -> Result<(), CliError> {
    let out_dir = PathBuf::from("out");
    fs::create_dir_all(&out_dir)?;
    let out_path = out_dir.join(format!("{}.json", file_stem));
    let serialized = serde_json::to_string_pretty(value)?;
    fs::write(out_path, serialized)?;
    Ok(())
}
