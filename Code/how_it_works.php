<?php
require_once __DIR__ . '/config.php';
require_login();

$user = current_user();
$pdo = get_db_connection();

// Get all enabled rules with their descriptions
$rulesStmt = $pdo->query('SELECT name, description, severity, rule_type, match_value FROM ids_rules WHERE enabled = 1 ORDER BY severity DESC, name');
$activeRules = $rulesStmt->fetchAll();

include __DIR__ . '/layout/header.php';
?>

<div class="card" style="margin-bottom: 1.5rem;">
    <div class="card-header">
        <div>
            <div class="card-title">Intrusion Detection Methodology</div>
            <div class="card-subtitle">Rule-based signature analysis engine</div>
        </div>
    </div>

    <div style="border-top: 1px solid #1f2937; padding-top: 1.5rem; margin-top: 1rem;">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
            <div style="padding: 1.25rem; background: linear-gradient(135deg, rgba(14,165,233,0.15), rgba(14,165,233,0.05)); border: 1px solid rgba(14,165,233,0.3); border-radius: 0.75rem;">
                <div style="font-size: 0.75rem; color: #7dd3fc; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Step 1</div>
                <div style="font-weight: 600; color: #e5e7eb; margin-bottom: 0.25rem;">Packet Capture</div>
                <div style="font-size: 0.85rem; color: #9ca3af;">PCAP file ingestion via pyshark parser</div>
            </div>
            <div style="padding: 1.25rem; background: linear-gradient(135deg, rgba(99,102,241,0.15), rgba(99,102,241,0.05)); border: 1px solid rgba(99,102,241,0.3); border-radius: 0.75rem;">
                <div style="font-size: 0.75rem; color: #a5b4fc; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Step 2</div>
                <div style="font-weight: 600; color: #e5e7eb; margin-bottom: 0.25rem;">Field Extraction</div>
                <div style="font-size: 0.85rem; color: #9ca3af;">IP, port, protocol, payload parsing</div>
            </div>
            <div style="padding: 1.25rem; background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(239,68,68,0.05)); border: 1px solid rgba(239,68,68,0.3); border-radius: 0.75rem;">
                <div style="font-size: 0.75rem; color: #fecaca; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Step 3</div>
                <div style="font-weight: 600; color: #e5e7eb; margin-bottom: 0.25rem;">Rule Matching</div>
                <div style="font-size: 0.85rem; color: #9ca3af;">Signature-based pattern detection</div>
            </div>
            <div style="padding: 1.25rem; background: linear-gradient(135deg, rgba(34,197,94,0.15), rgba(34,197,94,0.05)); border: 1px solid rgba(34,197,94,0.3); border-radius: 0.75rem;">
                <div style="font-size: 0.75rem; color: #86efac; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Step 4</div>
                <div style="font-weight: 600; color: #e5e7eb; margin-bottom: 0.25rem;">Alert Generation</div>
                <div style="font-size: 0.85rem; color: #9ca3af;">Severity classification & logging</div>
            </div>
        </div>

        <div style="background: #020617; border: 1px solid #1f2937; border-radius: 0.75rem; padding: 1.25rem; margin-bottom: 2rem;">
            <div style="font-size: 0.75rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1rem;">Extracted Packet Fields</div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem;">
                <div>
                    <div style="font-size: 0.8rem; color: #9ca3af; margin-bottom: 0.25rem;">Network Layer</div>
                    <div style="font-family: 'Courier New', monospace; font-size: 0.85rem; color: #e5e7eb;">
                        <div>• src_ip (IPv4/IPv6)</div>
                        <div>• dst_ip (IPv4/IPv6)</div>
                    </div>
                </div>
                <div>
                    <div style="font-size: 0.8rem; color: #9ca3af; margin-bottom: 0.25rem;">Transport Layer</div>
                    <div style="font-family: 'Courier New', monospace; font-size: 0.85rem; color: #e5e7eb;">
                        <div>• src_port (TCP/UDP)</div>
                        <div>• dst_port (TCP/UDP)</div>
                    </div>
                </div>
                <div>
                    <div style="font-size: 0.8rem; color: #9ca3af; margin-bottom: 0.25rem;">Application Layer</div>
                    <div style="font-family: 'Courier New', monospace; font-size: 0.85rem; color: #e5e7eb;">
                        <div>• protocol (L7)</div>
                        <div>• payload (raw bytes)</div>
                    </div>
                </div>
            </div>
        </div>

        <div style="background: #020617; border: 1px solid #1f2937; border-radius: 0.75rem; padding: 1.25rem;">
            <div style="font-size: 0.75rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1rem;">Detection Rule Types</div>
            <table class="table" style="margin-top: 0;">
                <thead>
                    <tr>
                        <th style="width: 30%;">Rule Type</th>
                        <th style="width: 20%;">Field</th>
                        <th>Detection Method</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><code style="background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 0.25rem;">src_ip</code></td>
                        <td>Source IP</td>
                        <td style="color: #9ca3af;">Exact match against source address</td>
                    </tr>
                    <tr>
                        <td><code style="background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 0.25rem;">dst_ip</code></td>
                        <td>Destination IP</td>
                        <td style="color: #9ca3af;">Exact match against destination address</td>
                    </tr>
                    <tr>
                        <td><code style="background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 0.25rem;">src_port</code></td>
                        <td>Source Port</td>
                        <td style="color: #9ca3af;">Numeric comparison on source port</td>
                    </tr>
                    <tr>
                        <td><code style="background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 0.25rem;">dst_port</code></td>
                        <td>Destination Port</td>
                        <td style="color: #9ca3af;">Numeric comparison on destination port</td>
                    </tr>
                    <tr>
                        <td><code style="background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 0.25rem;">protocol</code></td>
                        <td>Protocol</td>
                        <td style="color: #9ca3af;">Case-insensitive protocol name match</td>
                    </tr>
                    <tr>
                        <td><code style="background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 0.25rem;">payload_contains</code></td>
                        <td>Payload</td>
                        <td style="color: #9ca3af;">Case-insensitive substring search in packet data</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div class="card" style="margin-bottom: 1.5rem;">
    <div class="card-header">
        <div>
            <div class="card-title">Severity Classification</div>
            <div class="card-subtitle">Threat level assignment framework</div>
        </div>
    </div>

    <div style="border-top: 1px solid #1f2937; padding-top: 1.5rem; margin-top: 1rem;">
        <div style="display: grid; gap: 1rem;">
            <div style="padding: 1.25rem; background: linear-gradient(135deg, rgba(239,68,68,0.2), rgba(239,68,68,0.05)); border-left: 4px solid #ef4444; border-radius: 0.5rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem;">
                    <span class="badge badge-critical">CRITICAL</span>
                    <span style="font-weight: 600; color: #e5e7eb;">Immediate Threat Indicators</span>
                </div>
                <div style="font-size: 0.9rem; color: #d1d5db; line-height: 1.6;">
                    Remote access protocols (RDP, VNC), known malicious IP addresses from threat intelligence feeds, command & control (C2) communication patterns, critical service port exposure, lateral movement indicators.
                </div>
            </div>
            <div style="padding: 1.25rem; background: linear-gradient(135deg, rgba(250,204,21,0.2), rgba(250,204,21,0.05)); border-left: 4px solid #facc15; border-radius: 0.5rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem;">
                    <span class="badge badge-warning">WARNING</span>
                    <span style="font-weight: 600; color: #e5e7eb;">Suspicious Activity Patterns</span>
                </div>
                <div style="font-size: 0.9rem; color: #d1d5db; line-height: 1.6;">
                    Unencrypted protocols (Telnet, FTP), cleartext credential transmission, non-standard port usage, policy violations, reconnaissance activity, potential data exfiltration attempts.
                </div>
            </div>
            <div style="padding: 1.25rem; background: linear-gradient(135deg, rgba(56,189,248,0.2), rgba(56,189,248,0.05)); border-left: 4px solid #38bdf8; border-radius: 0.5rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem;">
                    <span class="badge badge-info">INFO</span>
                    <span style="font-weight: 600; color: #e5e7eb;">Informational Events</span>
                </div>
                <div style="font-size: 0.9rem; color: #d1d5db; line-height: 1.6;">
                    Baseline traffic patterns, compliance logging, audit trail events, low-risk protocol usage, network topology discovery.
                </div>
            </div>
        </div>
        <div style="margin-top: 1.5rem; padding: 1rem; background: rgba(56,189,248,0.08); border: 1px solid rgba(56,189,248,0.2); border-radius: 0.5rem;">
            <div style="font-size: 0.8rem; color: #7dd3fc; font-weight: 500; margin-bottom: 0.5rem;">ADMINISTRATIVE NOTE</div>
            <div style="font-size: 0.85rem; color: #9ca3af; line-height: 1.6;">
                Severity levels are manually assigned by administrators during rule creation. Classification is based on threat intelligence, organizational security policies, and risk assessment frameworks. Automatic severity calculation is not implemented in the current version.
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <div>
            <div class="card-title">Active Detection Signatures</div>
            <div class="card-subtitle">Enabled rule set currently analyzing PCAP traffic</div>
        </div>
    </div>

    <?php if (empty($activeRules)): ?>
        <div style="padding: 2rem; text-align: center; color: #6b7280;">
            <div style="font-size: 0.9rem;">No active signatures configured</div>
            <div style="font-size: 0.75rem; margin-top: 0.5rem; color: #4b5563;">Administrators can configure rules in the IDS Rules management interface</div>
        </div>
    <?php else: ?>
        <div style="border-top: 1px solid #1f2937; padding-top: 1.5rem; margin-top: 1rem;">
            <table class="table">
                <thead>
                    <tr>
                        <th style="width: 25%;">Signature Name</th>
                        <th style="width: 15%;">Type</th>
                        <th style="width: 20%;">Match Value</th>
                        <th style="width: 15%;">Severity</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($activeRules as $rule): ?>
                        <tr>
                            <td>
                                <div style="font-weight: 600; color: #e5e7eb;"><?php echo htmlspecialchars($rule['name']); ?></div>
                            </td>
                            <td>
                                <code style="background: #0f172a; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.8rem; color: #7dd3fc;"><?php echo htmlspecialchars($rule['rule_type']); ?></code>
                            </td>
                            <td>
                                <code style="background: #0f172a; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.8rem; color: #e5e7eb; font-family: 'Courier New', monospace;"><?php echo htmlspecialchars($rule['match_value']); ?></code>
                            </td>
                            <td>
                                <span class="badge <?php
                                    echo $rule['severity'] === 'critical' ? 'badge-critical' :
                                        ($rule['severity'] === 'warning' ? 'badge-warning' : 'badge-info');
                                ?>">
                                    <?php echo strtoupper(htmlspecialchars($rule['severity'])); ?>
                                </span>
                            </td>
                            <td style="color: #9ca3af; font-size: 0.85rem;">
                                <?php echo !empty($rule['description']) ? htmlspecialchars($rule['description']) : '<span style="color: #4b5563;">—</span>'; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<div class="card" style="margin-top: 1.5rem;">
    <div class="card-header">
        <div>
            <div class="card-title">Alert Interpretation</div>
            <div class="card-subtitle">Analysis workflow and investigation guidelines</div>
        </div>
    </div>

    <div style="border-top: 1px solid #1f2937; padding-top: 1.5rem; margin-top: 1rem;">
        <div style="background: #020617; border: 1px solid #1f2937; border-radius: 0.75rem; padding: 1.25rem; margin-bottom: 1.5rem;">
            <div style="font-size: 0.75rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1rem;">Alert Metadata Fields</div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                <div>
                    <div style="font-size: 0.8rem; color: #9ca3af; margin-bottom: 0.25rem;">Rule Identifier</div>
                    <div style="font-size: 0.9rem; color: #e5e7eb;">Detection rule name and description</div>
                </div>
                <div>
                    <div style="font-size: 0.8rem; color: #9ca3af; margin-bottom: 0.25rem;">Severity Classification</div>
                    <div style="font-size: 0.9rem; color: #e5e7eb;">Critical | Warning | Info</div>
                </div>
                <div>
                    <div style="font-size: 0.8rem; color: #9ca3af; margin-bottom: 0.25rem;">Network Flow</div>
                    <div style="font-size: 0.9rem; color: #e5e7eb; font-family: 'Courier New', monospace;">src_ip → dst_ip:port</div>
                </div>
                <div>
                    <div style="font-size: 0.8rem; color: #9ca3af; margin-bottom: 0.25rem;">Source File</div>
                    <div style="font-size: 0.9rem; color: #e5e7eb;">PCAP filename reference</div>
                </div>
            </div>
        </div>

        <div style="padding: 1.25rem; background: linear-gradient(135deg, rgba(250,204,21,0.15), rgba(250,204,21,0.05)); border-left: 4px solid #facc15; border-radius: 0.5rem; margin-bottom: 1.5rem;">
            <div style="font-weight: 600; color: #e5e7eb; margin-bottom: 0.75rem;">Investigation Protocol</div>
            <div style="font-size: 0.9rem; color: #d1d5db; line-height: 1.7;">
                Alert generation does not guarantee malicious activity. Each alert requires contextual analysis to distinguish between false positives, reconnaissance activity, policy violations, and confirmed threats. Correlation with additional security events and threat intelligence is recommended.
            </div>
        </div>

        <div style="background: #020617; border: 1px solid #1f2937; border-radius: 0.75rem; padding: 1.25rem;">
            <div style="font-size: 0.75rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1rem;">Common Detection Scenarios</div>
            <div style="display: grid; gap: 0.75rem;">
                <div style="padding: 0.75rem; background: #0f172a; border-radius: 0.5rem; border-left: 3px solid #ef4444;">
                    <div style="font-weight: 600; color: #e5e7eb; margin-bottom: 0.25rem;">RDP Exposure (Port 3389)</div>
                    <div style="font-size: 0.85rem; color: #9ca3af;">Remote Desktop Protocol traffic indicates potential unauthorized remote access vectors. High risk if exposed to external networks.</div>
                </div>
                <div style="padding: 0.75rem; background: #0f172a; border-radius: 0.5rem; border-left: 3px solid #facc15;">
                    <div style="font-weight: 600; color: #e5e7eb; margin-bottom: 0.25rem;">Telnet Protocol (Port 23)</div>
                    <div style="font-size: 0.85rem; color: #9ca3af;">Unencrypted remote terminal access. Commonly exploited for initial compromise and credential harvesting.</div>
                </div>
                <div style="padding: 0.75rem; background: #0f172a; border-radius: 0.5rem; border-left: 3px solid #ef4444;">
                    <div style="font-weight: 600; color: #e5e7eb; margin-bottom: 0.25rem;">Threat Intelligence IP Match</div>
                    <div style="font-size: 0.85rem; color: #9ca3af;">Communication with IP addresses listed in threat intelligence databases. Indicates potential C2 infrastructure or known malicious actors.</div>
                </div>
                <div style="padding: 0.75rem; background: #0f172a; border-radius: 0.5rem; border-left: 3px solid #facc15;">
                    <div style="font-weight: 600; color: #e5e7eb; margin-bottom: 0.25rem;">Credential Leakage Pattern</div>
                    <div style="font-size: 0.85rem; color: #9ca3af;">Payload analysis detects cleartext password transmission. Suggests insecure authentication mechanisms or credential theft attempts.</div>
                </div>
            </div>
        </div>
    </div>
</div>

<?php include __DIR__ . '/layout/footer.php'; ?>
