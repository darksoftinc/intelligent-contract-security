//Akıllı Kontratları analiz eden tüm modüller burada toplanacak.

use serde::{Serialize};
use std::collections::HashMap;

#[derive(Serialize, Clone)]
pub struct Vulnerability {
    pub name: String,
    pub line_number: usize,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub recommendation: String,
    pub cwe_id: String,
    pub impact: String,
}

#[derive(Serialize)]
pub struct AnalysisResult {
    pub vulnerabilities: Vec<Vulnerability>,
    pub summary: AnalysisSummary,
    pub metadata: AnalysisMetadata,
}

#[derive(Serialize)]
pub struct AnalysisSummary {
    pub total_vulnerabilities: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub security_score: u8,
    pub risk_level: String,
}

#[derive(Serialize)]
pub struct AnalysisMetadata {
    pub solidity_version: Option<String>,
    pub contract_count: usize,
    pub function_count: usize,
    pub line_count: usize,
    pub analysis_time: f64,
}

pub struct CodeLine {
    pub line_number: usize,
    pub content: String,
    pub context: String,
}

pub struct ContractContext {
    pub name: String,
    pub functions: Vec<String>,
    pub modifiers: Vec<String>,
    pub state_variables: Vec<String>,
    pub inheritance: Vec<String>,
}

//Bu fonksiyon, solidity okuyup satır satır codeline structlarını ayıracak
pub fn parse_solidity_code(code: &str) -> Vec<CodeLine> {
    let lines: Vec<&str> = code.lines().collect();
    let mut code_lines = Vec::new();
    
    for (i, line) in lines.iter().enumerate() {
        let context = get_line_context(&lines, i);
        code_lines.push(CodeLine {
            line_number: i + 1,
            content: line.to_string(),
            context,
        });
    }
    
    code_lines
}

fn get_line_context(lines: &[&str], current_line: usize) -> String {
    let start = current_line.saturating_sub(2);
    let end = (current_line + 3).min(lines.len());
    
    lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, line)| {
            if start + i == current_line {
                format!(">>> {}", line)
            } else {
                format!("    {}", line)
            }
        })
        .collect::<Vec<String>>()
        .join("\n")
}

// Gelişmiş zafiyet tespit sistemi
pub fn find_vulnerabilities(code_lines: &[CodeLine]) -> AnalysisResult {
    let start_time = std::time::Instant::now();
    
    let mut vulnerabilities = Vec::new();
    let contract_info = extract_contract_info(code_lines);
    
    // 1. Reentrancy Tespiti (Gelişmiş)
    vulnerabilities.extend(detect_reentrancy(code_lines, &contract_info));
    
    // 2. Integer Overflow/Underflow
    vulnerabilities.extend(detect_integer_overflow(code_lines));
    
    // 3. Access Control
    vulnerabilities.extend(detect_access_control(code_lines, &contract_info));
    
    // 4. Unchecked External Calls
    vulnerabilities.extend(detect_unchecked_calls(code_lines));
    
    // 5. Gas Optimization
    vulnerabilities.extend(detect_gas_issues(code_lines));
    
    // 6. Timestamp Dependence
    vulnerabilities.extend(detect_timestamp_dependence(code_lines));
    
    // 7. Random Number Generation
    vulnerabilities.extend(detect_random_generation(code_lines));
    
    // 8. Storage vs Memory
    vulnerabilities.extend(detect_storage_memory_issues(code_lines));
    
    // 9. Constructor Issues
    vulnerabilities.extend(detect_constructor_issues(code_lines));
    
    // 10. Fallback Function Issues
    vulnerabilities.extend(detect_fallback_issues(code_lines));
    
    let analysis_time = start_time.elapsed().as_secs_f64();
    let summary = calculate_summary(&vulnerabilities);
    let metadata = AnalysisMetadata {
        solidity_version: extract_solidity_version(code_lines),
        contract_count: contract_info.len(),
        function_count: count_functions(code_lines),
        line_count: code_lines.len(),
        analysis_time,
    };
    
    AnalysisResult {
        vulnerabilities,
        summary,
        metadata,
    }
}

fn detect_reentrancy(code_lines: &[CodeLine], _contract_info: &HashMap<String, ContractContext>) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    for line in code_lines {
        let content = line.content.to_lowercase();
        
        // External call patterns
        if content.contains("call.value") || content.contains("call{value:") {
            vulns.push(Vulnerability {
                name: "Reentrancy Attack".to_string(),
                line_number: line.line_number,
                description: "External call with value transfer before state update. This can lead to reentrancy attacks.".to_string(),
                severity: "Critical".to_string(),
                category: "Reentrancy".to_string(),
                recommendation: "Use ReentrancyGuard modifier, update state before external calls, or use pull pattern.".to_string(),
                cwe_id: "CWE-841".to_string(),
                impact: "Funds can be drained through recursive calls".to_string(),
            });
        }
        
        // Send/Transfer patterns
        if content.contains("send(") || content.contains("transfer(") {
            if !content.contains("require(") && !content.contains("assert(") {
                vulns.push(Vulnerability {
                    name: "Unchecked External Transfer".to_string(),
                    line_number: line.line_number,
                    description: "External transfer without checking return value. Transfer may fail silently.".to_string(),
                    severity: "High".to_string(),
                    category: "External Calls".to_string(),
                    recommendation: "Always check return values of send/transfer or use call with proper error handling.".to_string(),
                    cwe_id: "CWE-252".to_string(),
                    impact: "Failed transfers may not be detected".to_string(),
                });
            }
        }
    }
    
    vulns
}

fn detect_integer_overflow(code_lines: &[CodeLine]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    for line in code_lines {
        let content = line.content.to_lowercase();
        
        // Unchecked arithmetic
        if content.contains("unchecked") {
            vulns.push(Vulnerability {
                name: "Unchecked Arithmetic".to_string(),
                line_number: line.line_number,
                description: "Arithmetic operations in unchecked block can overflow/underflow without reverting.".to_string(),
                severity: "High".to_string(),
                category: "Integer Overflow".to_string(),
                recommendation: "Use SafeMath library or check for overflow/underflow conditions manually.".to_string(),
                cwe_id: "CWE-190".to_string(),
                impact: "Unexpected results and potential security vulnerabilities".to_string(),
            });
        }
        
        // Increment/decrement operations
        if content.contains("++") || content.contains("--") {
            vulns.push(Vulnerability {
                name: "Increment/Decrement Operation".to_string(),
                line_number: line.line_number,
                description: "Increment/decrement operations can overflow if not properly bounded.".to_string(),
                severity: "Medium".to_string(),
                category: "Integer Overflow".to_string(),
                recommendation: "Ensure variables have proper bounds and consider using SafeMath.".to_string(),
                cwe_id: "CWE-190".to_string(),
                impact: "Potential overflow in loop counters or state variables".to_string(),
            });
        }
    }
    
    vulns
}

fn detect_access_control(code_lines: &[CodeLine], _contract_info: &HashMap<String, ContractContext>) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    for line in code_lines {
        let content = line.content.to_lowercase();
        
        // tx.origin usage
        if content.contains("tx.origin") {
            vulns.push(Vulnerability {
                name: "Dangerous tx.origin Usage".to_string(),
                line_number: line.line_number,
                description: "tx.origin should not be used for authorization as it can be spoofed by contract calls.".to_string(),
                severity: "High".to_string(),
                category: "Access Control".to_string(),
                recommendation: "Use msg.sender instead of tx.origin for authorization checks.".to_string(),
                cwe_id: "CWE-477".to_string(),
                impact: "Authorization bypass through contract calls".to_string(),
            });
        }
        
        // Missing access modifiers
        if (content.contains("function") || content.contains("modifier")) && 
           !content.contains("public") && !content.contains("external") && 
           !content.contains("internal") && !content.contains("private") {
            vulns.push(Vulnerability {
                name: "Missing Access Modifier".to_string(),
                line_number: line.line_number,
                description: "Function or modifier lacks explicit access control, defaulting to public.".to_string(),
                severity: "Medium".to_string(),
                category: "Access Control".to_string(),
                recommendation: "Explicitly specify access modifiers for all functions and modifiers.".to_string(),
                cwe_id: "CWE-284".to_string(),
                impact: "Unauthorized access to functions or state variables".to_string(),
            });
        }
    }
    
    vulns
}

fn detect_unchecked_calls(code_lines: &[CodeLine]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    for line in code_lines {
        let content = line.content.to_lowercase();
        
        // Low-level calls without return value check
        if content.contains("call(") && !content.contains("require(") && !content.contains("assert(") {
            vulns.push(Vulnerability {
                name: "Unchecked Low-Level Call".to_string(),
                line_number: line.line_number,
                description: "Low-level call without checking return value. Call may fail silently.".to_string(),
                severity: "High".to_string(),
                category: "External Calls".to_string(),
                recommendation: "Always check return values of low-level calls and handle failures appropriately.".to_string(),
                cwe_id: "CWE-252".to_string(),
                impact: "Failed calls may not be detected, leading to unexpected behavior".to_string(),
            });
        }
    }
    
    vulns
}

fn detect_gas_issues(code_lines: &[CodeLine]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    for line in code_lines {
        let content = line.content.to_lowercase();
        
        // Infinite loops
        if content.contains("while") || content.contains("for") {
            if content.contains("gas") && content.contains("limit") {
                continue; // Has gas limit protection
            }
            vulns.push(Vulnerability {
                name: "Potential Infinite Loop".to_string(),
                line_number: line.line_number,
                description: "Loop without gas limit protection can cause transactions to fail.".to_string(),
                severity: "Medium".to_string(),
                category: "Gas Optimization".to_string(),
                recommendation: "Add gas limit checks or use bounded loops to prevent infinite execution.".to_string(),
                cwe_id: "CWE-400".to_string(),
                impact: "Transaction failures and potential DoS attacks".to_string(),
            });
        }
    }
    
    vulns
}

fn detect_timestamp_dependence(code_lines: &[CodeLine]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    for line in code_lines {
        let content = line.content.to_lowercase();
        
        if content.contains("block.timestamp") || content.contains("now") {
            vulns.push(Vulnerability {
                name: "Timestamp Dependence".to_string(),
                line_number: line.line_number,
                description: "Using block.timestamp for critical logic can be manipulated by miners.".to_string(),
                severity: "Medium".to_string(),
                category: "Randomness".to_string(),
                recommendation: "Avoid using block.timestamp for critical decisions. Consider using block numbers or external randomness.".to_string(),
                cwe_id: "CWE-754".to_string(),
                impact: "Predictable outcomes that can be exploited by miners".to_string(),
            });
        }
    }
    
    vulns
}

fn detect_random_generation(code_lines: &[CodeLine]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    for line in code_lines {
        let content = line.content.to_lowercase();
        
        if content.contains("blockhash") || content.contains("block.difficulty") {
            vulns.push(Vulnerability {
                name: "Weak Randomness Source".to_string(),
                line_number: line.line_number,
                description: "Blockchain variables are predictable and can be manipulated by miners.".to_string(),
                severity: "High".to_string(),
                category: "Randomness".to_string(),
                recommendation: "Use external randomness sources like Chainlink VRF or commit-reveal schemes.".to_string(),
                cwe_id: "CWE-338".to_string(),
                impact: "Predictable outcomes that can be exploited for unfair advantage".to_string(),
            });
        }
    }
    
    vulns
}

fn detect_storage_memory_issues(code_lines: &[CodeLine]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    for line in code_lines {
        let content = line.content.to_lowercase();
        
        if content.contains("storage") && content.contains("memory") {
            vulns.push(Vulnerability {
                name: "Storage vs Memory Confusion".to_string(),
                line_number: line.line_number,
                description: "Incorrect use of storage vs memory can lead to unexpected behavior and high gas costs.".to_string(),
                severity: "Medium".to_string(),
                category: "Gas Optimization".to_string(),
                recommendation: "Use storage for persistent data, memory for temporary data. Be explicit about data location.".to_string(),
                cwe_id: "CWE-665".to_string(),
                impact: "High gas costs and potential data corruption".to_string(),
            });
        }
    }
    
    vulns
}

fn detect_constructor_issues(code_lines: &[CodeLine]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    for line in code_lines {
        let content = line.content.to_lowercase();
        
        if content.contains("constructor") && content.contains("payable") {
            vulns.push(Vulnerability {
                name: "Payable Constructor".to_string(),
                line_number: line.line_number,
                description: "Payable constructor can receive ETH during deployment, potentially leading to locked funds.".to_string(),
                severity: "Low".to_string(),
                category: "Constructor".to_string(),
                recommendation: "Consider if constructor needs to be payable. If not, remove payable modifier.".to_string(),
                cwe_id: "CWE-754".to_string(),
                impact: "Potential for funds to be locked in contract during deployment".to_string(),
            });
        }
    }
    
    vulns
}

fn detect_fallback_issues(code_lines: &[CodeLine]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    for line in code_lines {
        let content = line.content.to_lowercase();
        
        if content.contains("fallback") || content.contains("receive") {
            vulns.push(Vulnerability {
                name: "Fallback/Receive Function".to_string(),
                line_number: line.line_number,
                description: "Fallback or receive functions can receive ETH and should have proper access controls.".to_string(),
                severity: "Medium".to_string(),
                category: "Fallback Functions".to_string(),
                recommendation: "Implement proper access controls and consider if ETH reception is intended.".to_string(),
                cwe_id: "CWE-284".to_string(),
                impact: "Unauthorized ETH reception and potential DoS attacks".to_string(),
            });
        }
    }
    
    vulns
}

fn extract_contract_info(code_lines: &[CodeLine]) -> HashMap<String, ContractContext> {
    let mut contracts = HashMap::new();
    let mut current_contract = None;
    
    for line in code_lines {
        let content = line.content.trim();
        
        if content.starts_with("contract ") {
            if let Some(name) = content.split_whitespace().nth(1) {
                let clean_name = name.replace("{", "").trim().to_string();
                current_contract = Some(clean_name.clone());
                contracts.insert(clean_name.clone(), ContractContext {
                    name: clean_name,
                    functions: Vec::new(),
                    modifiers: Vec::new(),
                    state_variables: Vec::new(),
                    inheritance: Vec::new(),
                });
            }
        }
        
        if let Some(contract_name) = &current_contract {
            if let Some(contract) = contracts.get_mut(contract_name) {
                if content.starts_with("function ") {
                    if let Some(func_name) = content.split_whitespace().nth(1) {
                        contract.functions.push(func_name.to_string());
                    }
                } else if content.starts_with("modifier ") {
                    if let Some(mod_name) = content.split_whitespace().nth(1) {
                        contract.modifiers.push(mod_name.to_string());
                    }
                }
            }
        }
    }
    
    contracts
}

fn extract_solidity_version(code_lines: &[CodeLine]) -> Option<String> {
    for line in code_lines {
        let content = line.content.trim();
        if content.starts_with("pragma solidity") {
            return Some(content.to_string());
        }
    }
    None
}

fn count_functions(code_lines: &[CodeLine]) -> usize {
    code_lines.iter()
        .filter(|line| line.content.trim().starts_with("function "))
        .count()
}

fn calculate_summary(vulnerabilities: &[Vulnerability]) -> AnalysisSummary {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    
    for vuln in vulnerabilities {
        match vuln.severity.as_str() {
            "Critical" => critical += 1,
            "High" => high += 1,
            "Medium" => medium += 1,
            "Low" => low += 1,
            _ => {}
        }
    }
    
    let total = vulnerabilities.len();
    let security_score = calculate_security_score(critical, high, medium, low);
    let risk_level = determine_risk_level(security_score);
    
    AnalysisSummary {
        total_vulnerabilities: total,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        security_score,
        risk_level,
    }
}

fn calculate_security_score(critical: usize, high: usize, medium: usize, low: usize) -> u8 {
    let mut score: i32 = 100;
    score = score.saturating_sub((critical * 30) as i32);
    score = score.saturating_sub((high * 20) as i32);
    score = score.saturating_sub((medium * 10) as i32);
    score = score.saturating_sub((low * 5) as i32);
    score.max(0) as u8
}

fn determine_risk_level(score: u8) -> String {
    match score {
        90..=100 => "Low Risk".to_string(),
        70..=89 => "Medium Risk".to_string(),
        40..=69 => "High Risk".to_string(),
        _ => "Critical Risk".to_string(),
    }
}