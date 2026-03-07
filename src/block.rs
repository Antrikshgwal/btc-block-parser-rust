use crate::merkle::compute_merkle;
use crate::transactions::{TransactionReport, analyze_transaction_for_block};
use crate::undo::{Prevout as UndoPrevout, parse_txin_undo};
use crate::{CliError, xor::XorReader};
use bitcoin::hex::DisplayHex;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

pub struct InternalInput {
    pub prevout: Option<UndoPrevout>,
}

pub struct InternalTx {
    pub txid_raw: [u8; 32],
    pub inputs: Vec<InternalInput>,
    pub raw_bytes: Vec<u8>,
}

pub struct ParsedBlock {
    pub header: BlockHeader,
    pub header_raw: [u8; 80],
    pub transactions: Vec<InternalTx>,
}

pub struct BlockHeader {
    pub version: u32,
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

#[derive(Debug, Serialize)]
pub struct BlockReport {
    pub ok: bool,
    pub mode: &'static str,
    pub block_header: BlockHeaderReport,
    pub tx_count: usize,
    pub coinbase: CoinbaseReport,
    pub transactions: Vec<TransactionReport>,
    pub block_stats: BlockStatsReport,
}

#[derive(Debug, Serialize)]
pub struct BlockHeaderReport {
    pub version: u32,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub merkle_root_valid: bool,
    pub timestamp: u32,
    pub bits: String,
    pub nonce: u32,
    pub block_hash: String,
}

#[derive(Debug, Serialize)]
pub struct CoinbaseReport {
    pub bip34_height: u64,
    pub coinbase_script_hex: String,
    pub total_output_sats: u64,
}

#[derive(Debug, Serialize)]
pub struct BlockStatsReport {
    pub total_fees_sats: u64,
    pub total_weight: u64,
    pub avg_fee_rate_sat_vb: f64,
    pub script_type_summary: HashMap<String, u64>,
}

const MAINNET_MAGIC: u32 = 0xD9B4BEF9;

fn to_hex_reversed(bytes: &[u8; 32]) -> String {
    let mut rev = *bytes;
    rev.reverse();
    rev.to_lower_hex_string()
}

fn extract_bip34_height(coinbase_tx: &bitcoin::Transaction) -> u64 {
    let bytes = coinbase_tx.input[0].script_sig.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    let push_len = bytes[0] as usize;
    if push_len == 0 || push_len > 8 || bytes.len() < 1 + push_len {
        return 0;
    }
    let mut height: u64 = 0;
    for i in 0..push_len {
        height |= (bytes[1 + i] as u64) << (8 * i);
    }
    height
}

pub fn analyze_blocks(blk_path: &Path, rev_path: &Path, xor_path: &Path) -> Result<(), CliError> {
    let key = std::fs::read(xor_path)?;
    let blk_file = File::open(blk_path)?;
    let blk_reader = BufReader::new(blk_file);
    let xor_blk = XorReader::new(blk_reader, key.clone());

    let rev_file = File::open(rev_path)?;
    let rev_reader = BufReader::new(rev_file);
    let xor_rev = XorReader::new(rev_reader, key);

    stream_blocks(xor_blk, xor_rev, |block| {
        let block_hash = dsha256(&block.header_raw);
        let block_hash_hex = to_hex_reversed(&block_hash);

        let cb_raw = &block.transactions[0].raw_bytes;
        let cb_tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(cb_raw)
            .map_err(|e| format!("coinbase decode: {}", e))?;
        let coinbase_script_hex = cb_tx.input[0].script_sig.as_bytes().to_lower_hex_string();
        let total_cb_output: u64 = cb_tx.output.iter().map(|o| o.value.to_sat()).sum();
        let bip34_height = extract_bip34_height(&cb_tx);

        let mut all_reports: Vec<TransactionReport> = Vec::new();
        let mut total_fees: u64 = 0;
        let mut total_weight: u64 = 0;
        let mut total_non_cb_vbytes: u64 = 0;
        let mut script_type_summary: HashMap<String, u64> = HashMap::new();

        for (tx_idx, internal_tx) in block.transactions.iter().enumerate() {
            let decoded: bitcoin::Transaction =
                bitcoin::consensus::encode::deserialize(&internal_tx.raw_bytes)
                    .map_err(|e| format!("tx {} decode: {}", tx_idx, e))?;

            let mut prevout_map: HashMap<(String, u32), crate::Prevout> = HashMap::new();
            if tx_idx > 0 {
                for (vin_idx, input) in decoded.input.iter().enumerate() {
                    if let Some(ref undo_prev) = internal_tx.inputs[vin_idx].prevout {
                        let txid_str = input.previous_output.txid.to_string();
                        let vout = input.previous_output.vout;
                        prevout_map.insert(
                            (txid_str.clone(), vout),
                            crate::Prevout {
                                txid: txid_str,
                                vout,
                                value_sats: undo_prev.value_sats,
                                script_pubkey_hex: undo_prev.script_pubkey.to_lower_hex_string(),
                            },
                        );
                    }
                }
            }

            let report = analyze_transaction_for_block("mainnet", &decoded, &prevout_map)
                .map_err(|e| e.to_string())?;

            // Accumulate stats
            total_weight += report.weight;
            for v in &report.vout {
                *script_type_summary
                    .entry(v.script_type.clone())
                    .or_insert(0) += 1;
            }
            if tx_idx > 0 {
                total_fees += report.fee_sats;
                total_non_cb_vbytes += report.vbytes;
            }

            all_reports.push(report);
        }

        let avg_fee_rate = if total_non_cb_vbytes > 0 {
            total_fees as f64 / total_non_cb_vbytes as f64
        } else {
            0.0
        };

        let block_report = BlockReport {
            ok: true,
            mode: "block",
            block_header: BlockHeaderReport {
                version: block.header.version,
                prev_block_hash: to_hex_reversed(&block.header.prev_block_hash),
                merkle_root: to_hex_reversed(&block.header.merkle_root),
                merkle_root_valid: true,
                timestamp: block.header.timestamp,
                bits: format!("{:08x}", block.header.bits),
                nonce: block.header.nonce,
                block_hash: block_hash_hex.clone(),
            },
            tx_count: block.transactions.len(),
            coinbase: CoinbaseReport {
                bip34_height,
                coinbase_script_hex,
                total_output_sats: total_cb_output,
            },
            transactions: all_reports,
            block_stats: BlockStatsReport {
                total_fees_sats: total_fees,
                total_weight,
                avg_fee_rate_sat_vb: avg_fee_rate,
                script_type_summary,
            },
        };

        crate::write_report_to_out(&block_hash_hex, &block_report).map_err(|e| e.to_string())?;

        let pretty = serde_json::to_string_pretty(&block_report).map_err(|e| e.to_string())?;
        println!("{}", pretty);

        Ok(())
    })
    .map_err(|e| CliError::InvalidTx(e))?;

    Ok(())
}

fn collect_rev_entries<R: Read>(mut rev: R) -> Result<Vec<Vec<u8>>, String> {
    let mut entries = Vec::new();
    loop {
        let magic = match rev.read_u32::<LittleEndian>() {
            Ok(m) => m,
            Err(_) => break, // EOF
        };
        if magic != MAINNET_MAGIC {
            break;
        }
        let rev_size = rev
            .read_u32::<LittleEndian>()
            .map_err(|_| "rev size read error".to_string())?;
        let mut data = vec![0u8; rev_size as usize];
        rev.read_exact(&mut data)
            .map_err(|_| "rev data read error".to_string())?;
        // Skip 32-byte checksum
        let mut _checksum = [0u8; 32];
        rev.read_exact(&mut _checksum)
            .map_err(|_| "rev checksum skip fail".to_string())?;
        entries.push(data);
    }
    Ok(entries)
}

fn peek_undo_tx_count(data: &[u8]) -> Result<u64, String> {
    let mut cursor = std::io::Cursor::new(data);
    read_compactsize(&mut cursor)
}

pub fn stream_blocks<R: Read>(
    mut blk: R,
    rev: R,
    mut handle: impl FnMut(ParsedBlock) -> Result<(), String>,
) -> Result<(), String> {
    let rev_entries = collect_rev_entries(rev)?;

    let magic = match blk.read_u32::<LittleEndian>() {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    if magic != MAINNET_MAGIC {
        return Err("invalid magic".into());
    }

    let size = blk
        .read_u32::<LittleEndian>()
        .map_err(|_| "block size read error".to_string())?;

    let mut limited_blk = blk.by_ref().take(size as u64);
    let mut block = parse_block(&mut limited_blk)?;

    let expected_undo_count = (block.transactions.len() - 1) as u64;

    let mut matched = false;
    for entry_data in &rev_entries {
        if let Ok(undo_tx_count) = peek_undo_tx_count(entry_data) {
            if undo_tx_count == expected_undo_count {
                let mut cursor = std::io::Cursor::new(entry_data);
                attach_undo(&mut cursor, &mut block)?;
                matched = true;
                break;
            }
        }
    }

    if !matched {
        return Err(format!(
            "no matching undo entry found for block with {} txs (expected {} undo txs, checked {} rev entries)",
            block.transactions.len(),
            expected_undo_count,
            rev_entries.len()
        ));
    }

    handle(block)?;

    Ok(())
}

fn read_compactsize<R: Read>(r: &mut R) -> Result<u64, String> {
    let first = r
        .read_u8()
        .map_err(|_| "compactsize read error".to_string())?;
    match first {
        0..=0xfc => Ok(first as u64),
        0xfd => r
            .read_u16::<LittleEndian>()
            .map(|v| v as u64)
            .map_err(|_| "compactsize u16 read error".to_string()),
        0xfe => r
            .read_u32::<LittleEndian>()
            .map(|v| v as u64)
            .map_err(|_| "compactsize u32 read error".to_string()),
        0xff => r
            .read_u64::<LittleEndian>()
            .map_err(|_| "compactsize u64 read error".to_string()),
    }
}

fn read_bytes<R: Read>(r: &mut R, len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .map_err(|_| "read_bytes failed".to_string())?;
    Ok(buf)
}

fn dsha256(data: &[u8]) -> [u8; 32] {
    crate::merkle::dsha256(data)
}

fn parse_transaction_streaming<R: Read>(r: &mut R) -> Result<InternalTx, String> {
    let mut raw = Vec::new();
    let mut raw_no_witness = Vec::new();

    let version_bytes = read_bytes(r, 4)?;
    raw.extend_from_slice(&version_bytes);
    raw_no_witness.extend_from_slice(&version_bytes);

    let mut peek = [0u8; 1];
    r.read_exact(&mut peek).map_err(|_| "tx peek".to_string())?;
    raw.push(peek[0]);

    let is_segwit = peek[0] == 0x00;
    let vin_count;

    if is_segwit {
        // read flag byte
        let mut flag = [0u8; 1];
        r.read_exact(&mut flag).map_err(|_| "tx flag".to_string())?;
        raw.push(flag[0]);
        if flag[0] != 0x01 {
            return Err("unexpected segwit flag".into());
        }
        vin_count = read_compactsize(r)?;
        let vc = encode_compactsize(vin_count);
        raw.extend_from_slice(&vc);
        raw_no_witness.extend_from_slice(&vc);
    } else {
        let vc_rest = finish_compactsize(peek[0], r)?;
        vin_count = vc_rest.0;
        raw.extend_from_slice(&vc_rest.1[1..]); // already pushed peek[0]
        raw_no_witness.extend_from_slice(&vc_rest.1);
    }

    // ── inputs ────────────────────────────────────
    let mut inputs = Vec::with_capacity(vin_count as usize);
    for _ in 0..vin_count {
        let txid = read_bytes(r, 32)?;
        let vout = read_bytes(r, 4)?;
        let script_len = read_compactsize(r)?;
        let script_sig = read_bytes(r, script_len as usize)?;
        let sequence = read_bytes(r, 4)?;

        let mut chunk = Vec::new();
        chunk.extend_from_slice(&txid);
        chunk.extend_from_slice(&vout);
        chunk.extend_from_slice(&encode_compactsize(script_len));
        chunk.extend_from_slice(&script_sig);
        chunk.extend_from_slice(&sequence);

        raw.extend_from_slice(&chunk);
        raw_no_witness.extend_from_slice(&chunk);

        inputs.push(InternalInput { prevout: None });
    }

    // ── outputs ───────────────────────────────────
    let vout_count = read_compactsize(r)?;
    let vc = encode_compactsize(vout_count);
    raw.extend_from_slice(&vc);
    raw_no_witness.extend_from_slice(&vc);

    for _ in 0..vout_count {
        let value = read_bytes(r, 8)?;
        let script_len = read_compactsize(r)?;
        let script = read_bytes(r, script_len as usize)?;

        let mut chunk = Vec::new();
        chunk.extend_from_slice(&value);
        chunk.extend_from_slice(&encode_compactsize(script_len));
        chunk.extend_from_slice(&script);

        raw.extend_from_slice(&chunk);
        raw_no_witness.extend_from_slice(&chunk);
    }

    // ── witness (segwit only) ─────────────────────
    if is_segwit {
        for _ in 0..vin_count {
            let item_count = read_compactsize(r)?;
            let ic = encode_compactsize(item_count);
            raw.extend_from_slice(&ic);
            for _ in 0..item_count {
                let wlen = read_compactsize(r)?;
                let wdata = read_bytes(r, wlen as usize)?;
                raw.extend_from_slice(&encode_compactsize(wlen));
                raw.extend_from_slice(&wdata);
            }
        }
    }

    // ── locktime (4 bytes) ────────────────────────
    let locktime = read_bytes(r, 4)?;
    raw.extend_from_slice(&locktime);
    raw_no_witness.extend_from_slice(&locktime);

    // ── txid ──────────────────────────────────────
    let txid_raw = dsha256(&raw_no_witness);

    Ok(InternalTx {
        txid_raw,
        inputs,
        raw_bytes: raw,
    })
}

fn encode_compactsize(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

fn finish_compactsize<R: Read>(first: u8, r: &mut R) -> Result<(u64, Vec<u8>), String> {
    match first {
        0..=0xfc => Ok((first as u64, vec![first])),
        0xfd => {
            let lo = r
                .read_u16::<LittleEndian>()
                .map_err(|_| "compactsize u16".to_string())?;
            let mut b = vec![first];
            b.extend_from_slice(&lo.to_le_bytes());
            Ok((lo as u64, b))
        }
        0xfe => {
            let lo = r
                .read_u32::<LittleEndian>()
                .map_err(|_| "compactsize u32".to_string())?;
            let mut b = vec![first];
            b.extend_from_slice(&lo.to_le_bytes());
            Ok((lo as u64, b))
        }
        0xff => {
            let lo = r
                .read_u64::<LittleEndian>()
                .map_err(|_| "compactsize u64".to_string())?;
            let mut b = vec![first];
            b.extend_from_slice(&lo.to_le_bytes());
            Ok((lo, b))
        }
    }
}

// ── Single-block parser ──────────────────────────────────────────────

fn parse_block<R: Read>(r: &mut R) -> Result<ParsedBlock, String> {
    let mut header_bytes = [0u8; 80];
    r.read_exact(&mut header_bytes)
        .map_err(|_| "header".to_string())?;

    let mut cur = &header_bytes[..];

    let version = cur.read_u32::<LittleEndian>().unwrap();
    let mut prev = [0u8; 32];
    cur.read_exact(&mut prev).unwrap();
    let mut merkle = [0u8; 32];
    cur.read_exact(&mut merkle).unwrap();
    let timestamp = cur.read_u32::<LittleEndian>().unwrap();
    let bits = cur.read_u32::<LittleEndian>().unwrap();
    let nonce = cur.read_u32::<LittleEndian>().unwrap();

    let tx_count = read_compactsize(r)?;

    let mut txids = Vec::with_capacity(tx_count as usize);
    let mut txs = Vec::with_capacity(tx_count as usize);

    for _ in 0..tx_count {
        let tx = parse_transaction_streaming(r)?;
        txids.push(tx.txid_raw);
        txs.push(tx);
    }

    let calc_merkle = compute_merkle(txids);

    if calc_merkle != merkle {
        return Err("merkle mismatch".into());
    }

    Ok(ParsedBlock {
        header: BlockHeader {
            version,
            prev_block_hash: prev,
            merkle_root: merkle,
            timestamp,
            bits,
            nonce,
        },
        header_raw: header_bytes,
        transactions: txs,
    })
}

// ── Undo attachment ──────────────────────────────────────────────────

fn attach_undo<R: Read>(r: &mut R, block: &mut ParsedBlock) -> Result<(), String> {
    // Bitcoin Core serializes vector lengths as CompactSize, not base128 varint
    let undo_tx_count = read_compactsize(r)?;

    if undo_tx_count != (block.transactions.len() - 1) as u64 {
        return Err(format!(
            "undo count mismatch: got {} undo txs, expected {} (block has {} txs)",
            undo_tx_count,
            block.transactions.len() - 1,
            block.transactions.len()
        ));
    }

    for tx_index in 1..block.transactions.len() {
        let input_count = read_compactsize(r)?;

        if input_count != block.transactions[tx_index].inputs.len() as u64 {
            return Err("undo input mismatch".into());
        }

        for vin in &mut block.transactions[tx_index].inputs {
            let prevout = parse_txin_undo(r).map_err(|_| "undo parse fail".to_string())?;
            vin.prevout = Some(prevout);
        }
    }

    Ok(())
}
