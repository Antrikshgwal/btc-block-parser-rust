use bitcoin::{
    Address, Network, ScriptBuf, Transaction, consensus::encode, hashes::hex::FromHex,
    hex::DisplayHex,
};
use serde::Serialize;
use std::collections::HashMap;

use crate::{CliError, Fixture, Prevout};

#[derive(Debug, Serialize)]
pub struct TransactionReport {
    pub ok: bool,
    pub mode: &'static str,
    pub network: String,
    pub segwit: bool,
    pub txid: String,
    pub wtxid: Option<String>,
    pub version: i32,
    pub locktime: u32,
    pub size_bytes: usize,
    pub weight: u64,
    pub vbytes: u64,
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub fee_sats: u64,
    pub fee_rate_sat_vb: f64,
    pub rbf_signaling: bool,
    pub locktime_type: String,
    pub locktime_value: u32,
    pub segwit_savings: Option<SegwitSavingsReport>,
    pub vin: Vec<VinReport>,
    pub vout: Vec<VoutReport>,
    pub warnings: Vec<WarningReport>,
}

#[derive(Debug, Serialize)]
pub struct SegwitSavingsReport {
    pub witness_bytes: usize,
    pub non_witness_bytes: usize,
    pub total_bytes: usize,
    pub weight_actual: u64,
    pub weight_if_legacy: u64,
    pub savings_pct: f64,
}

#[derive(Debug, Serialize)]
pub struct VinReport {
    pub txid: String,
    pub vout: u32,
    pub sequence: u32,
    pub script_sig_hex: String,
    pub script_asm: String,
    pub witness: Vec<String>,
    pub script_type: String,
    pub address: Option<String>,
    pub prevout: Option<PrevoutReport>,
    pub relative_timelock: RelativeTimelockReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_script_asm: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PrevoutReport {
    pub value_sats: u64,
    pub script_pubkey_hex: String,
}

#[derive(Debug, Serialize)]
pub struct RelativeTimelockReport {
    pub enabled: bool,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u32>,
}

impl RelativeTimelockReport {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            kind: None,
            value: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VoutReport {
    pub n: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_asm: String,
    pub script_type: String,
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_data_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_data_utf8: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_protocol: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WarningReport {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub fn decode_transaction(raw_hex: &str) -> Result<Transaction, CliError> {
    let bytes =
        Vec::<u8>::from_hex(raw_hex).map_err(|err| CliError::InvalidHex(err.to_string()))?;
    let tx: Transaction = encode::deserialize(&bytes)?;
    Ok(tx)
}

fn classify_output_script(script: &ScriptBuf) -> String {
    if script.is_p2pkh() {
        "p2pkh".to_string()
    } else if script.is_p2sh() {
        "p2sh".to_string()
    } else if script.is_p2wpkh() {
        "p2wpkh".to_string()
    } else if script.is_p2wsh() {
        "p2wsh".to_string()
    } else if script.is_p2tr() {
        "p2tr".to_string()
    } else if script.is_op_return() {
        "op_return".to_string()
    } else {
        "unknown".to_string()
    }
}

fn script_to_address(script: &ScriptBuf, network: Network) -> Option<String> {
    Address::from_script(script, network)
        .ok()
        .map(|addr| addr.to_string())
}

fn disassemble_script(script: &ScriptBuf) -> String {
    let bytes = script.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let opcode = bytes[i];
        i += 1;

        // Handle OP_0
        if opcode == 0x00 {
            result.push("OP_0".to_string());
            continue;
        }

        if opcode >= 0x51 && opcode <= 0x60 {
            result.push(format!("OP_{}", opcode - 0x50));
            continue;
        }

        if opcode >= 0x01 && opcode <= 0x4b {
            let len = opcode as usize;
            if i + len <= bytes.len() {
                let data = &bytes[i..i + len];
                result.push(format!(
                    "OP_PUSHBYTES_{} {}",
                    len,
                    data.to_lower_hex_string()
                ));
                i += len;
            } else {
                result.push(format!("OP_PUSHBYTES_{} <truncated>", len));
                break;
            }
            continue;
        }

        if opcode == 0x4c {
            if i < bytes.len() {
                let len = bytes[i] as usize;
                i += 1;
                if i + len <= bytes.len() {
                    let data = &bytes[i..i + len];
                    result.push(format!("OP_PUSHDATA1 {}", data.to_lower_hex_string()));
                    i += len;
                } else {
                    result.push("OP_PUSHDATA1 <truncated>".to_string());
                    break;
                }
            }
            continue;
        }

        if opcode == 0x4d {
            if i + 1 < bytes.len() {
                let len = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
                i += 2;
                if i + len <= bytes.len() {
                    let data = &bytes[i..i + len];
                    result.push(format!("OP_PUSHDATA2 {}", data.to_lower_hex_string()));
                    i += len;
                } else {
                    result.push("OP_PUSHDATA2 <truncated>".to_string());
                    break;
                }
            }
            continue;
        }

        if opcode == 0x4e {
            if i + 3 < bytes.len() {
                let len = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
                    as usize;
                i += 4;
                if i + len <= bytes.len() {
                    let data = &bytes[i..i + len];
                    result.push(format!("OP_PUSHDATA4 {}", data.to_lower_hex_string()));
                    i += len;
                } else {
                    result.push("OP_PUSHDATA4 <truncated>".to_string());
                    break;
                }
            }
            continue;
        }

        let opcode_name = match opcode {
            0x61 => "OP_NOP",
            0x76 => "OP_DUP",
            0x87 => "OP_EQUAL",
            0x88 => "OP_EQUALVERIFY",
            0xa9 => "OP_HASH160",
            0xaa => "OP_HASH256",
            0xac => "OP_CHECKSIG",
            0xad => "OP_CHECKSIGVERIFY",
            0xae => "OP_CHECKMULTISIG",
            0xaf => "OP_CHECKMULTISIGVERIFY",
            0x6a => "OP_RETURN",
            _ => {
                result.push(format!("OP_UNKNOWN_{:#04x}", opcode));
                continue;
            }
        };
        result.push(opcode_name.to_string());
    }

    result.join(" ")
}

fn extract_op_return_data(script: &ScriptBuf) -> (String, Option<String>, String) {
    let bytes = script.as_bytes();

    if bytes.is_empty() || bytes[0] != 0x6a {
        return (String::new(), None, "unknown".to_string());
    }

    let mut data = Vec::new();
    let mut i = 1; // Skip OP_RETURN

    // Extract all data pushes
    while i < bytes.len() {
        let opcode = bytes[i];
        i += 1;

        // Direct push (1-75 bytes)
        if opcode >= 0x01 && opcode <= 0x4b {
            let len = opcode as usize;
            if i + len <= bytes.len() {
                data.extend_from_slice(&bytes[i..i + len]);
                i += len;
            } else {
                break;
            }
            continue;
        }

        // OP_PUSHDATA1
        if opcode == 0x4c && i < bytes.len() {
            let len = bytes[i] as usize;
            i += 1;
            if i + len <= bytes.len() {
                data.extend_from_slice(&bytes[i..i + len]);
                i += len;
            } else {
                break;
            }
            continue;
        }

        // OP_PUSHDATA2
        if opcode == 0x4d && i + 1 < bytes.len() {
            let len = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
            i += 2;
            if i + len <= bytes.len() {
                data.extend_from_slice(&bytes[i..i + len]);
                i += len;
            } else {
                break;
            }
            continue;
        }

        // OP_PUSHDATA4
        if opcode == 0x4e && i + 3 < bytes.len() {
            let len =
                u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
            i += 4;
            if i + len <= bytes.len() {
                data.extend_from_slice(&bytes[i..i + len]);
                i += len;
            } else {
                break;
            }
            continue;
        }

        break;
    }

    let data_hex = data.to_lower_hex_string();
    let data_utf8 = std::str::from_utf8(&data).ok().map(|s| s.to_string());

    // Detect protocol
    let protocol = if data.starts_with(&[0x6f, 0x6d, 0x6e, 0x69]) {
        // "omni"
        "omni".to_string()
    } else if data.starts_with(&[0x01, 0x09, 0xf9, 0x11, 0x02]) {
        "opentimestamps".to_string()
    } else {
        "unknown".to_string()
    };

    (data_hex, data_utf8, protocol)
}

fn classify_input_script(
    prevout_script: &ScriptBuf,
    script_sig: &ScriptBuf,
    has_witness: bool,
    witness_len: usize,
) -> String {
    // P2PKH: non-empty scriptSig, no witness
    if prevout_script.is_p2pkh() {
        return "p2pkh".to_string();
    }

    // P2WPKH: empty scriptSig, witness with 2 items
    if prevout_script.is_p2wpkh() {
        return "p2wpkh".to_string();
    }

    // P2WSH: empty scriptSig, witness with 2+ items
    if prevout_script.is_p2wsh() {
        return "p2wsh".to_string();
    }

    // P2TR: empty scriptSig, witness
    if prevout_script.is_p2tr() {
        if witness_len == 1 {
            return "p2tr_keypath".to_string();
        } else {
            return "p2tr_scriptpath".to_string();
        }
    }

    // P2SH: check for nested SegWit
    if prevout_script.is_p2sh() {
        if !script_sig.is_empty() && has_witness {
            // Nested SegWit - check witness count
            if witness_len == 2 {
                return "p2sh-p2wpkh".to_string();
            } else if witness_len > 2 {
                return "p2sh-p2wsh".to_string();
            }
        }
        return "unknown".to_string();
    }

    "unknown".to_string()
}

fn parse_relative_timelock(sequence: u32) -> RelativeTimelockReport {
    if sequence & (1 << 31) != 0 {
        return RelativeTimelockReport::disabled();
    }

    if sequence == 0xffffffff {
        return RelativeTimelockReport::disabled();
    }

    let value = (sequence & 0xffff) as u32;

    if sequence & (1 << 22) != 0 {
        RelativeTimelockReport {
            enabled: true,
            kind: Some("time".to_string()),
            value: Some(value * 512),
        }
    } else {
        RelativeTimelockReport {
            enabled: true,
            kind: Some("blocks".to_string()),
            value: Some(value),
        }
    }
}

pub fn analyze_transaction(
    fixture: &Fixture,
    tx: &Transaction,
) -> Result<TransactionReport, CliError> {
    let segwit = tx.input.iter().any(|input| !input.witness.is_empty());
    let locktime = tx.lock_time.to_consensus_u32();
    let size_bytes = encode::serialize(tx).len();
    let weight = tx.weight().to_wu() as u64;
    let vbytes = (weight + 3) / 4;
    let total_output_sats: u64 = tx.output.iter().map(|out| out.value.to_sat()).sum();

    let prevout_map = match_prevouts(tx, &fixture.prevouts)?;

    let total_input_sats: u64 = tx
        .input
        .iter()
        .map(|input| {
            let key = (
                input.previous_output.txid.to_string(),
                input.previous_output.vout,
            );
            prevout_map.get(&key).unwrap().value_sats
        })
        .sum();

    let fee_sats = total_input_sats.saturating_sub(total_output_sats);
    let fee_rate_sat_vb = if vbytes > 0 {
        fee_sats as f64 / vbytes as f64
    } else {
        0.0
    };

    let rbf_signaling = tx.input.iter().any(|input| input.sequence.0 < 0xfffffffe);

    let (locktime_type, locktime_value) = classify_locktime(locktime);

    // Parse network
    let network = match fixture.network.as_str() {
        "mainnet" => Network::Bitcoin,
        _ => Network::Bitcoin,
    };

    // Parse inputs
    let mut vin_reports = Vec::new();
    for input in &tx.input {
        let txid = input.previous_output.txid.to_string();
        let vout = input.previous_output.vout;
        let sequence = input.sequence.0;

        //Get prevout info
        let key = (txid.clone(), vout);
        let prevout = prevout_map.get(&key).unwrap();

        // Parse prevout script
        let prevout_script_bytes = Vec::<u8>::from_hex(&prevout.script_pubkey_hex)
            .map_err(|e| CliError::InvalidHex(e.to_string()))?;
        let prevout_script = ScriptBuf::from_bytes(prevout_script_bytes);

        let script_sig = &input.script_sig;
        let script_sig_hex = script_sig.as_bytes().to_lower_hex_string();
        let script_asm = disassemble_script(script_sig);

        // Format witness
        let witness: Vec<String> = input
            .witness
            .iter()
            .map(|item| item.to_lower_hex_string())
            .collect();

        let has_witness = !witness.is_empty();
        let witness_len = witness.len();

        // Classify input type
        let script_type =
            classify_input_script(&prevout_script, script_sig, has_witness, witness_len);

        // Derive address from prevout
        let address = script_to_address(&prevout_script, network);

        // Parse relative timelock
        let relative_timelock = parse_relative_timelock(sequence);

        let witness_script_asm =
            if (script_type == "p2wsh" || script_type == "p2sh-p2wsh") && !witness.is_empty() {
                let witness_script_hex = witness.last().unwrap();
                let witness_script_bytes = Vec::<u8>::from_hex(witness_script_hex)
                    .map_err(|e| CliError::InvalidHex(e.to_string()))?;
                let witness_script = ScriptBuf::from_bytes(witness_script_bytes);
                Some(disassemble_script(&witness_script))
            } else {
                None
            };

        vin_reports.push(VinReport {
            txid,
            vout,
            sequence,
            script_sig_hex,
            script_asm,
            witness,
            script_type,
            address,
            prevout: Some(PrevoutReport {
                value_sats: prevout.value_sats,
                script_pubkey_hex: prevout.script_pubkey_hex.clone(),
            }),
            relative_timelock,
            witness_script_asm,
        });
    }

    // Parse outputs
    let mut vout_reports = Vec::new();
    for (n, output) in tx.output.iter().enumerate() {
        let script = &output.script_pubkey;
        let script_type = classify_output_script(script);
        let script_asm = disassemble_script(script);
        let address = if script_type != "op_return" && script_type != "unknown" {
            script_to_address(script, network)
        } else {
            None
        };

        let (op_return_data_hex, op_return_data_utf8, op_return_protocol) =
            if script_type == "op_return" {
                let (hex, utf8, protocol) = extract_op_return_data(script);
                (Some(hex), utf8, Some(protocol))
            } else {
                (None, None, None)
            };

        vout_reports.push(VoutReport {
            n: n as u32,
            value_sats: output.value.to_sat(),
            script_pubkey_hex: script.as_bytes().to_lower_hex_string(),
            script_asm,
            script_type,
            address,
            op_return_data_hex,
            op_return_data_utf8,
            op_return_protocol,
        });
    }

    // SegWit savings calculations
    let segwit_savings = if segwit {
        // Calculate witness bytes
        let mut witness_bytes = 0u64;
        for input in &tx.input {
            if !input.witness.is_empty() {
                witness_bytes += 1;
                for item in &input.witness {
                    let item_len = item.len();
                    if item_len < 253 {
                        witness_bytes += 1 + item_len as u64;
                    } else if item_len <= 0xffff {
                        witness_bytes += 3 + item_len as u64;
                    } else {
                        witness_bytes += 5 + item_len as u64;
                    }
                }
            }
        }

        let total_bytes = size_bytes as u64;
        let non_witness_bytes = total_bytes - witness_bytes - 2; // -2 for marker and flag
        let weight_actual = weight;
        let weight_if_legacy = (non_witness_bytes * 4) + (witness_bytes * 4);
        let savings_pct = if weight_if_legacy > 0 {
            ((weight_if_legacy - weight_actual) as f64 / weight_if_legacy as f64 * 100.0 * 100.0)
                .round()
                / 100.0
        } else {
            0.0
        };

        Some(SegwitSavingsReport {
            witness_bytes: witness_bytes as usize,
            non_witness_bytes: non_witness_bytes as usize,
            total_bytes: total_bytes as usize,
            weight_actual,
            weight_if_legacy,
            savings_pct,
        })
    } else {
        None
    };

    let mut warnings = Vec::new();

    // HIGH_FEE: fee > 1M sats OR fee rate > 200 sat/vB
    if fee_sats > 1_000_000 || fee_rate_sat_vb > 200.0 {
        warnings.push(WarningReport {
            code: "HIGH_FEE".to_string(),
            message: None,
        });
    }

    for output_report in &vout_reports {
        if output_report.script_type != "op_return" && output_report.value_sats < 546 {
            warnings.push(WarningReport {
                code: "DUST_OUTPUT".to_string(),
                message: None,
            });
            break; // Only emit once
        }
    }

    // UNKNOWN_OUTPUT_SCRIPT
    if vout_reports.iter().any(|v| v.script_type == "unknown") {
        warnings.push(WarningReport {
            code: "UNKNOWN_OUTPUT_SCRIPT".to_string(),
            message: None,
        });
    }

    // RBF_SIGNALING
    if rbf_signaling {
        warnings.push(WarningReport {
            code: "RBF_SIGNALING".to_string(),
            message: None,
        });
    }

    Ok(TransactionReport {
        ok: true,
        mode: "transaction",
        network: fixture.network.clone(),
        segwit,
        txid: tx.compute_txid().to_string(),
        wtxid: if segwit {
            Some(tx.compute_wtxid().to_string())
        } else {
            None
        },
        version: tx.version.0,
        locktime,
        size_bytes,
        weight,
        vbytes,
        total_input_sats,
        total_output_sats,
        fee_sats,
        fee_rate_sat_vb,
        rbf_signaling,
        locktime_type,
        locktime_value,
        segwit_savings,
        vin: vin_reports,
        vout: vout_reports,
        warnings,
    })
}

pub fn analyze_transaction_for_block(
    network_str: &str,
    tx: &Transaction,
    prevout_map: &HashMap<(String, u32), Prevout>,
) -> Result<TransactionReport, CliError> {
    let segwit = tx.input.iter().any(|input| !input.witness.is_empty());
    let locktime = tx.lock_time.to_consensus_u32();
    let size_bytes = encode::serialize(tx).len();
    let weight = tx.weight().to_wu() as u64;
    let vbytes = (weight + 3) / 4;
    let total_output_sats: u64 = tx.output.iter().map(|out| out.value.to_sat()).sum();

    // Check if this is coinbase (empty prevout map for coinbase)
    let is_coinbase = prevout_map.is_empty();

    // Calculate total input value
    let total_input_sats: u64 = if is_coinbase {
        0
    } else {
        tx.input
            .iter()
            .map(|input| {
                let key = (
                    input.previous_output.txid.to_string(),
                    input.previous_output.vout,
                );
                prevout_map.get(&key).map(|p| p.value_sats).unwrap_or(0)
            })
            .sum()
    };

    let fee_sats = total_input_sats.saturating_sub(total_output_sats);
    let fee_rate_sat_vb = if vbytes > 0 {
        fee_sats as f64 / vbytes as f64
    } else {
        0.0
    };

    let rbf_signaling = tx.input.iter().any(|input| input.sequence.0 < 0xfffffffe);

    let (locktime_type, locktime_value) = classify_locktime(locktime);

    // Parse network
    let network = match network_str {
        "mainnet" => Network::Bitcoin,
        _ => Network::Bitcoin,
    };

    // Parse inputs
    let mut vin_reports = Vec::new();
    for input in &tx.input {
        let txid = input.previous_output.txid.to_string();
        let vout = input.previous_output.vout;
        let sequence = input.sequence.0;

        let script_sig = &input.script_sig;
        let script_sig_hex = script_sig.as_bytes().to_lower_hex_string();
        let script_asm = disassemble_script(script_sig);

        // Format witness
        let witness: Vec<String> = input
            .witness
            .iter()
            .map(|item| item.to_lower_hex_string())
            .collect();

        let has_witness = !witness.is_empty();
        let witness_len = witness.len();

        // Get prevout info (if not coinbase)
        let (script_type, address, prevout_report, witness_script_asm) = if is_coinbase {
            ("coinbase".to_string(), None, None, None)
        } else {
            let key = (txid.clone(), vout);
            if let Some(prevout) = prevout_map.get(&key) {
                // Parse prevout script
                let prevout_script_bytes = Vec::<u8>::from_hex(&prevout.script_pubkey_hex)
                    .map_err(|e| CliError::InvalidHex(e.to_string()))?;
                let prevout_script = ScriptBuf::from_bytes(prevout_script_bytes);

                // Classify input type
                let script_type =
                    classify_input_script(&prevout_script, script_sig, has_witness, witness_len);

                // Derive address from prevout
                let address = script_to_address(&prevout_script, network);

                let witness_script_asm = if (script_type == "p2wsh" || script_type == "p2sh-p2wsh")
                    && !witness.is_empty()
                {
                    let witness_script_hex = witness.last().unwrap();
                    let witness_script_bytes = Vec::<u8>::from_hex(witness_script_hex)
                        .map_err(|e| CliError::InvalidHex(e.to_string()))?;
                    let witness_script = ScriptBuf::from_bytes(witness_script_bytes);
                    Some(disassemble_script(&witness_script))
                } else {
                    None
                };

                let prevout_report = Some(PrevoutReport {
                    value_sats: prevout.value_sats,
                    script_pubkey_hex: prevout.script_pubkey_hex.clone(),
                });

                (script_type, address, prevout_report, witness_script_asm)
            } else {
                ("unknown".to_string(), None, None, None)
            }
        };

        // Parse relative timelock
        let relative_timelock = parse_relative_timelock(sequence);

        vin_reports.push(VinReport {
            txid,
            vout,
            sequence,
            script_sig_hex,
            script_asm,
            witness,
            script_type,
            address,
            prevout: prevout_report,
            relative_timelock,
            witness_script_asm,
        });
    }

    // Parse outputs
    let mut vout_reports = Vec::new();
    for (n, output) in tx.output.iter().enumerate() {
        let script = &output.script_pubkey;
        let script_type = classify_output_script(script);
        let script_asm = disassemble_script(script);
        let address = if script_type != "op_return" && script_type != "unknown" {
            script_to_address(script, network)
        } else {
            None
        };

        let (op_return_data_hex, op_return_data_utf8, op_return_protocol) =
            if script_type == "op_return" {
                let (hex, utf8, protocol) = extract_op_return_data(script);
                (Some(hex), utf8, Some(protocol))
            } else {
                (None, None, None)
            };

        vout_reports.push(VoutReport {
            n: n as u32,
            value_sats: output.value.to_sat(),
            script_pubkey_hex: script.as_bytes().to_lower_hex_string(),
            script_asm,
            script_type,
            address,
            op_return_data_hex,
            op_return_data_utf8,
            op_return_protocol,
        });
    }

    // Calculate SegWit savings if applicable
    let segwit_savings = if segwit {
        // Calculate witness bytes
        let mut witness_bytes = 0u64;
        for input in &tx.input {
            if !input.witness.is_empty() {
                witness_bytes += 1;
                for item in &input.witness {
                    let item_len = item.len();
                    if item_len < 253 {
                        witness_bytes += 1 + item_len as u64;
                    } else if item_len <= 0xffff {
                        witness_bytes += 3 + item_len as u64;
                    } else {
                        witness_bytes += 5 + item_len as u64;
                    }
                }
            }
        }

        let total_bytes = size_bytes as u64;
        let non_witness_bytes = total_bytes - witness_bytes - 2; // -2 for marker and flag
        let weight_actual = weight;
        let weight_if_legacy = (non_witness_bytes * 4) + (witness_bytes * 4);
        let savings_pct = if weight_if_legacy > 0 {
            ((weight_if_legacy - weight_actual) as f64 / weight_if_legacy as f64 * 100.0 * 100.0)
                .round()
                / 100.0
        } else {
            0.0
        };

        Some(SegwitSavingsReport {
            witness_bytes: witness_bytes as usize,
            non_witness_bytes: non_witness_bytes as usize,
            total_bytes: total_bytes as usize,
            weight_actual,
            weight_if_legacy,
            savings_pct,
        })
    } else {
        None
    };


    let mut warnings = Vec::new();

    if fee_sats > 1_000_000 || fee_rate_sat_vb > 200.0 {
        warnings.push(WarningReport {
            code: "HIGH_FEE".to_string(),
            message: None,
        });
    }

    for output_report in &vout_reports {
        if output_report.script_type != "op_return" && output_report.value_sats < 546 {
            warnings.push(WarningReport {
                code: "DUST_OUTPUT".to_string(),
                message: None,
            });
            break; // Only emit once
        }
    }

    if vout_reports.iter().any(|v| v.script_type == "unknown") {
        warnings.push(WarningReport {
            code: "UNKNOWN_OUTPUT_SCRIPT".to_string(),
            message: None,
        });
    }

    // RBF_SIGNALING
    if rbf_signaling {
        warnings.push(WarningReport {
            code: "RBF_SIGNALING".to_string(),
            message: None,
        });
    }

    Ok(TransactionReport {
        ok: true,
        mode: "transaction",
        network: network_str.to_string(),
        segwit,
        txid: tx.compute_txid().to_string(),
        wtxid: if segwit {
            Some(tx.compute_wtxid().to_string())
        } else {
            None
        },
        version: tx.version.0,
        locktime,
        size_bytes,
        weight,
        vbytes,
        total_input_sats,
        total_output_sats,
        fee_sats,
        fee_rate_sat_vb,
        rbf_signaling,
        locktime_type,
        locktime_value,
        segwit_savings,
        vin: vin_reports,
        vout: vout_reports,
        warnings,
    })
}

fn classify_locktime(raw: u32) -> (String, u32) {
    if raw == 0 {
        ("none".to_string(), 0)
    } else if raw < 500_000_000 {
        ("block_height".to_string(), raw)
    } else {
        ("unix_timestamp".to_string(), raw)
    }
}

fn match_prevouts<'a>(
    tx: &Transaction,
    prevouts: &'a [Prevout],
) -> Result<HashMap<(String, u32), &'a Prevout>, CliError> {
    // Build a map of (txid, vout) -> Prevout
    let mut prevout_map: HashMap<(String, u32), &'a Prevout> = HashMap::new();

    for prevout in prevouts {
        let key = (prevout.txid.clone(), prevout.vout);
        if prevout_map.contains_key(&key) {
            return Err(CliError::InvalidTx(format!(
                "Duplicate prevout: {}:{}",
                prevout.txid, prevout.vout
            )));
        }
        prevout_map.insert(key, prevout);
    }

    // Validate that all inputs have corresponding prevouts
    for input in &tx.input {
        let txid = input.previous_output.txid.to_string();
        let vout = input.previous_output.vout;
        let key = (txid.clone(), vout);

        if !prevout_map.contains_key(&key) {
            return Err(CliError::InvalidTx(format!(
                "Missing prevout for input: {}:{}",
                txid, vout
            )));
        }
    }

    // Validate that there are no extra prevouts
    if prevout_map.len() != tx.input.len() {
        return Err(CliError::InvalidTx(
            "Prevout count does not match input count".to_string(),
        ));
    }

    Ok(prevout_map)
}
