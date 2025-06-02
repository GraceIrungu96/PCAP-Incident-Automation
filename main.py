import asyncio
import csv
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib
import ipaddress
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

import httpx
from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest
import pandas as pd

# Configuration
GROQ_API_KEY = "API_KEY"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Email Configuration
SMTP_SERVER = "smtp.company.com"  # Configure your SMTP server
SMTP_PORT = 587
SMTP_USERNAME = "graceirungu96@gmail.com"
SMTP_PASSWORD = "bnspesnfheazammh"  # Use environment variable in production
SOC_MANAGER_EMAIL = "graceirungu96@gmail.com"

STORAGE_DIR = Path("soc_alerts")
EVIDENCE_DIR = STORAGE_DIR / "evidence"
ALERTS_DIR = STORAGE_DIR / "alerts"

# Ensure directories exist
STORAGE_DIR.mkdir(exist_ok=True)
EVIDENCE_DIR.mkdir(exist_ok=True)
ALERTS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="SOC Packet Analysis Automation", version="2.0.0")

# Enhanced Data Models
class PacketAnalysis(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    timestamp: float
    payload_size: int
    dns_query: Optional[str] = None
    http_host: Optional[str] = None
    http_uri: Optional[str] = None
    flags: Optional[str] = None

class ThreatIndicator(BaseModel):
    indicator_type: str  # ip, domain, hash, etc.
    value: str
    confidence: float
    description: str

class SecurityAlert(BaseModel):
    incident_id: str
    incident_name: str
    criticality: str  # High, Medium, Low
    timestamp: datetime
    key_findings: Dict[str, Any]
    ai_recommendation: str
    evidence_file: str
    threat_indicators: List[ThreatIndicator]
    affected_hosts: List[str]
    c2_indicators: List[str]
    email_sent: bool = False
    human_approved: Optional[bool] = None
    approval_timestamp: Optional[datetime] = None

class AnalysisResult(BaseModel):
    analysis_id: str
    packet_count: int
    suspicious_packets: int
    alerts_generated: int
    status: str
    evidence_files: List[str]
    notifications_sent: Dict[str, bool]

# Threat Intelligence and Suspicious Indicators
SUSPICIOUS_DOMAINS = [
    "pastebin.com", "bit.ly", "tinyurl.com", "t.co", 
    "raw.githubusercontent.com", "discord.com/api/webhooks",
    "dropbox.com", "mega.nz", "file.io", "transfer.sh"
]

SUSPICIOUS_PORTS = [4444, 5555, 8080, 1337, 31337, 6666, 7777, 9999, 1234, 4321]

C2_SIGNATURES = [
    "beacon", "heartbeat", "checkin", "implant", 
    "payload", "download", "upload", "execute", "cmd", "shell"
]

MALICIOUS_USER_AGENTS = [
    "curl", "wget", "python-requests", "powershell", "empire"
]

class EmailNotifier:
    def __init__(self, smtp_server: str, smtp_port: int, username: str, password: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
    
    async def send_alert_notification(self, alert: SecurityAlert, evidence_file_path: str) -> bool:
        """Send email notification to SOC manager"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.username
            msg['To'] = SOC_MANAGER_EMAIL
            msg['Subject'] = f"🚨 {alert.criticality} Priority Alert: {alert.incident_name}"
            
            # Create email body
            body = self._create_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Attach evidence file
            if os.path.exists(evidence_file_path):
                with open(evidence_file_path, "rb") as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {os.path.basename(evidence_file_path)}'
                )
                msg.attach(part)
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            text = msg.as_string()
            server.sendmail(self.username, SOC_MANAGER_EMAIL, text)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"Failed to send email notification: {e}")
            return False
    
    def _create_email_body(self, alert: SecurityAlert) -> str:
        """Create HTML email body"""
        
        # Determine emoji based on criticality
        emoji = "🔴" if alert.criticality == "High" else "🟡" if alert.criticality == "Medium" else "🟢"
        
        # Format timestamp
        timestamp_str = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Format key findings
        key_findings_html = ""
        if alert.key_findings.get("source_ips"):
            key_findings_html += f"<li><strong>Source IPs:</strong> {', '.join(alert.key_findings['source_ips'][:5])}</li>"
        if alert.key_findings.get("destination_ips"):
            key_findings_html += f"<li><strong>Destination IPs:</strong> {', '.join(alert.key_findings['destination_ips'][:5])}</li>"
        if alert.c2_indicators:
            key_findings_html += f"<li><strong>C2 Indicators:</strong> {', '.join(alert.c2_indicators[:3])}</li>"
        key_findings_html += f"<li><strong>Threat Count:</strong> {alert.key_findings.get('threat_count', 0)}</li>"
        key_findings_html += f"<li><strong>Packets Analyzed:</strong> {alert.key_findings.get('packet_count', 0)}</li>"
        
        # Format threat indicators
        threat_indicators_html = ""
        for threat in alert.threat_indicators[:5]:  # Show top 5 threats
            confidence_color = "#ff4444" if threat.confidence >= 0.8 else "#ff8800" if threat.confidence >= 0.5 else "#ffaa00"
            threat_indicators_html += f"""
            <tr>
                <td>{threat.indicator_type.title()}</td>
                <td><code>{threat.value}</code></td>
                <td style="color: {confidence_color}; font-weight: bold;">{threat.confidence:.1%}</td>
                <td>{threat.description}</td>
            </tr>
            """
        
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f8f9fa; padding: 15px; border-left: 5px solid #dc3545; }}
                .content {{ margin: 20px 0; }}
                .section {{ margin: 15px 0; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .high {{ color: #dc3545; }}
                .medium {{ color: #fd7e14; }}
                .low {{ color: #28a745; }}
                code {{ background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>{emoji} Security Alert: {alert.incident_name}</h2>
                <p><strong>Incident ID:</strong> {alert.incident_id}</p>
                <p><strong>Criticality:</strong> <span class="{alert.criticality.lower()}">{alert.criticality}</span></p>
                <p><strong>Timestamp:</strong> {timestamp_str}</p>
            </div>
            
            <div class="content">
                <div class="section">
                    <h3>🔍 Key Findings</h3>
                    <ul>
                        {key_findings_html}
                    </ul>
                </div>
                
                <div class="section">
                    <h3>⚠️ Threat Indicators</h3>
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Value</th>
                            <th>Confidence</th>
                            <th>Description</th>
                        </tr>
                        {threat_indicators_html}
                    </table>
                </div>
                
                <div class="section">
                    <h3>🤖 AI Recommendation</h3>
                    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px;">
                        {alert.ai_recommendation.replace(chr(10), '<br>')}
                    </div>
                </div>
                
                <div class="section">
                    <h3>📎 Evidence</h3>
                    <p>Detailed evidence has been attached as a CSV file: <strong>{alert.evidence_file}</strong></p>
                    <p>Additional threat indicators file may also be attached.</p>
                </div>
                
                <hr>
                <p><em>This alert was generated automatically by the SOC Packet Analysis System.</em></p>
                <p><em>Please review and take appropriate action. Approve or reject this alert through the SOC dashboard.</em></p>
            </div>
        </body>
        </html>
        """
        
        return html_body

class PacketAnalyzer:
    def __init__(self):
        self.analysis_cache = {}
        
    def analyze_packet_capture(self, pcap_file: str) -> List[PacketAnalysis]:
        """Analyze packet capture file and extract relevant data"""
        packets = scapy.rdpcap(pcap_file)
        analyses = []
        
        for packet in packets:
            if IP in packet:
                analysis = self._analyze_packet(packet)
                if analysis:
                    analyses.append(analysis)
                    
        return analyses
    
    def _analyze_packet(self, packet) -> Optional[PacketAnalysis]:
        """Analyze individual packet"""
        try:
            ip_layer = packet[IP]
            
            # Map IP protocol numbers to names
            protocol_map = {
                1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 4: "IPv4",
                41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF"
            }
            
            protocol_num = ip_layer.proto
            protocol_name = protocol_map.get(protocol_num, f"Protocol-{protocol_num}")
            
            analysis = PacketAnalysis(
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                protocol=protocol_name,
                timestamp=float(packet.time),
                payload_size=len(packet)
            )
            
            # TCP Analysis
            if TCP in packet:
                tcp_layer = packet[TCP]
                analysis.src_port = tcp_layer.sport
                analysis.dst_port = tcp_layer.dport
                analysis.flags = str(tcp_layer.flags)
                analysis.protocol = "TCP"
                
            # UDP Analysis
            elif UDP in packet:
                udp_layer = packet[UDP]
                analysis.src_port = udp_layer.sport
                analysis.dst_port = udp_layer.dport
                analysis.protocol = "UDP"
            
            # DNS Analysis
            if DNS in packet and DNSQR in packet:
                dns_layer = packet[DNSQR]
                analysis.dns_query = dns_layer.qname.decode('utf-8').rstrip('.')
                
            # HTTP Analysis
            if HTTPRequest in packet:
                http_layer = packet[HTTPRequest]
                analysis.http_host = http_layer.Host.decode('utf-8') if http_layer.Host else None
                analysis.http_uri = http_layer.Path.decode('utf-8') if http_layer.Path else None
                
            return analysis
            
        except Exception as e:
            print(f"Error analyzing packet: {e}")
            return None

class ThreatDetector:
    def __init__(self):
        self.suspicious_ips = set()
        self.c2_domains = set()
        
    def detect_threats(self, analyses: List[PacketAnalysis]) -> List[ThreatIndicator]:
        """Detect threats in packet analyses"""
        threats = []
        
        # Group by source IP for behavioral analysis
        ip_behaviors = {}
        for analysis in analyses:
            if analysis.src_ip not in ip_behaviors:
                ip_behaviors[analysis.src_ip] = []
            ip_behaviors[analysis.src_ip].append(analysis)
            
        # Detect suspicious behaviors
        for src_ip, packets in ip_behaviors.items():
            threats.extend(self._detect_c2_communication(src_ip, packets))
            threats.extend(self._detect_suspicious_domains(src_ip, packets))
            threats.extend(self._detect_port_scanning(src_ip, packets))
            threats.extend(self._detect_data_exfiltration(src_ip, packets))
            
        return threats
    
    def _detect_c2_communication(self, src_ip: str, packets: List[PacketAnalysis]) -> List[ThreatIndicator]:
        """Detect command and control communication patterns"""
        threats = []
        
        # Look for regular beaconing patterns
        timestamps = [p.timestamp for p in packets]
        if len(timestamps) > 5:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals)
            
            # Regular intervals might indicate beaconing
            regular_intervals = sum(1 for interval in intervals if abs(interval - avg_interval) < 5)
            if regular_intervals / len(intervals) > 0.8:
                threats.append(ThreatIndicator(
                    indicator_type="behavior",
                    value=f"regular_beaconing_{src_ip}",
                    confidence=0.8,
                    description=f"Regular beaconing pattern detected from {src_ip}"
                ))
        
        # Check for suspicious ports
        for packet in packets:
            if packet.dst_port in SUSPICIOUS_PORTS:
                threats.append(ThreatIndicator(
                    indicator_type="network",
                    value=f"{packet.dst_ip}:{packet.dst_port}",
                    confidence=0.7,
                    description=f"Communication to suspicious port {packet.dst_port}"
                ))
                
        return threats
    
    def _detect_suspicious_domains(self, src_ip: str, packets: List[PacketAnalysis]) -> List[ThreatIndicator]:
        """Detect communication to suspicious domains"""
        threats = []
        
        for packet in packets:
            if packet.dns_query:
                for suspicious_domain in SUSPICIOUS_DOMAINS:
                    if suspicious_domain in packet.dns_query:
                        threats.append(ThreatIndicator(
                            indicator_type="domain",
                            value=packet.dns_query,
                            confidence=0.6,
                            description=f"DNS query to suspicious domain: {packet.dns_query}"
                        ))
                        
            if packet.http_host:
                for suspicious_domain in SUSPICIOUS_DOMAINS:
                    if suspicious_domain in packet.http_host:
                        threats.append(ThreatIndicator(
                            indicator_type="domain",
                            value=packet.http_host,
                            confidence=0.7,
                            description=f"HTTP communication to suspicious domain: {packet.http_host}"
                        ))
                        
        return threats
    
    def _detect_port_scanning(self, src_ip: str, packets: List[PacketAnalysis]) -> List[ThreatIndicator]:
        """Detect port scanning behavior"""
        threats = []
        
        # Count unique destination ports
        dst_ports = set()
        dst_ips = set()
        
        for packet in packets:
            if packet.dst_port:
                dst_ports.add(packet.dst_port)
                dst_ips.add(packet.dst_ip)
        
        # If many ports on few IPs, likely port scan
        if len(dst_ports) > 10 and len(dst_ips) < 5:
            threats.append(ThreatIndicator(
                indicator_type="behavior",
                value=f"port_scan_{src_ip}",
                confidence=0.9,
                description=f"Port scanning detected from {src_ip} ({len(dst_ports)} ports scanned)"
            ))
            
        return threats
    
    def _detect_data_exfiltration(self, src_ip: str, packets: List[PacketAnalysis]) -> List[ThreatIndicator]:
        """Detect potential data exfiltration"""
        threats = []
        
        # Calculate total outbound data
        outbound_data = sum(p.payload_size for p in packets)
        
        # Large amounts of outbound data might indicate exfiltration
        if outbound_data > 10_000_000:  # 10MB threshold
            threats.append(ThreatIndicator(
                indicator_type="behavior",
                value=f"data_exfiltration_{src_ip}",
                confidence=0.6,
                description=f"Large data transfer detected from {src_ip} ({outbound_data/1_000_000:.1f}MB)"
            ))
            
        return threats

class AIAnalyzer:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.client = httpx.AsyncClient(timeout=30.0)
        
    async def generate_alert(self, threats: List[ThreatIndicator], 
                           packet_analyses: List[PacketAnalysis]) -> SecurityAlert:
        """Generate security alert using AI analysis"""
        
        # Prepare context for AI
        context = self._prepare_analysis_context(threats, packet_analyses)
        
        # Get AI analysis
        ai_response = await self._call_groq_api(context)
        
        # Parse AI response and create alert
        alert = self._create_alert_from_ai_response(ai_response, threats, packet_analyses)
        
        return alert
    
    def _prepare_analysis_context(self, threats: List[ThreatIndicator], 
                                packet_analyses: List[PacketAnalysis]) -> str:
        """Prepare analysis context for AI"""
        
        # Summarize packet data
        unique_src_ips = set(p.src_ip for p in packet_analyses)
        unique_dst_ips = set(p.dst_ip for p in packet_analyses)
        protocols = set(p.protocol for p in packet_analyses)
        
        context = f"""
Network Traffic Analysis Summary:
- Total packets analyzed: {len(packet_analyses)}
- Unique source IPs: {len(unique_src_ips)} ({list(unique_src_ips)[:5]})
- Unique destination IPs: {len(unique_dst_ips)} ({list(unique_dst_ips)[:5]})
- Protocols observed: {list(protocols)}

Threat Indicators Detected ({len(threats)}):
"""
        
        for threat in threats:
            context += f"- {threat.indicator_type}: {threat.value} (confidence: {threat.confidence:.1f}) - {threat.description}\n"
            
        context += """
Please analyze this network traffic and provide:
1. A concise incident name (one line)
2. Criticality level (High, Medium, Low)
3. Key findings summary
4. Specific containment and remediation recommendations
5. Assessment of potential C2 communication or malicious activity

Focus on actionable recommendations for the SOC team.
"""
        
        return context
    
    async def _call_groq_api(self, context: str) -> Dict[str, Any]:
        """Call Groq API for AI analysis"""
        
        payload = {
            "model": "meta-llama/llama-4-scout-17b-16e-instruct",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert analyzing network traffic for threats. Provide clear, actionable security analysis with specific containment and remediation steps."
                },
                {
                    "role": "user",
                    "content": context
                }
            ],
            "temperature": 0.1,
            "max_tokens": 1000
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = await self.client.post(GROQ_API_URL, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error calling Groq API: {e}")
            return {"choices": [{"message": {"content": "AI analysis unavailable - manual review required. Immediate containment recommended for High priority threats."}}]}
    
    def _create_alert_from_ai_response(self, ai_response: Dict[str, Any], 
                                     threats: List[ThreatIndicator],
                                     packet_analyses: List[PacketAnalysis]) -> SecurityAlert:
        """Create security alert from AI response"""
        
        ai_content = ai_response.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        # Extract key information
        incident_name = self._extract_incident_name(ai_content)
        criticality = self._extract_criticality(ai_content)
        
        # Generate incident ID
        incident_id = f"SOC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
        
        # Collect key findings
        unique_src_ips = list(set(p.src_ip for p in packet_analyses))
        unique_dst_ips = list(set(p.dst_ip for p in packet_analyses))
        threat_count = len(threats)
        
        key_findings = {
            "source_ips": unique_src_ips[:10],  # Limit to top 10
            "destination_ips": unique_dst_ips[:10],
            "threat_count": threat_count,
            "packet_count": len(packet_analyses),
            "protocols": list(set(p.protocol for p in packet_analyses)),
            "suspicious_ports": list(set(p.dst_port for p in packet_analyses if p.dst_port in SUSPICIOUS_PORTS))
        }
        
        # Extract C2 indicators
        c2_indicators = []
        for threat in threats:
            if "c2" in threat.description.lower() or "beacon" in threat.description.lower():
                c2_indicators.append(f"{threat.indicator_type}: {threat.value}")
        
        # Affected hosts (unique source IPs)
        affected_hosts = unique_src_ips[:5]
        
        # Generate evidence filename
        evidence_file = f"evidence_{incident_id}.csv"
        
        alert = SecurityAlert(
            incident_id=incident_id,
            incident_name=incident_name,
            criticality=criticality,
            timestamp=datetime.now(timezone.utc),
            key_findings=key_findings,
            ai_recommendation=ai_content,
            evidence_file=evidence_file,
            threat_indicators=threats,
            affected_hosts=affected_hosts,
            c2_indicators=c2_indicators
        )
        
        return alert
    
    def _extract_incident_name(self, ai_content: str) -> str:
        """Extract incident name from AI response"""
        lines = ai_content.split('\n')
        for line in lines:
            if any(keyword in line.lower() for keyword in ['incident', 'alert', 'threat', 'attack']):
                # Clean up the line and use as incident name
                cleaned = line.strip().replace('*', '').replace('#', '').replace('-', '').strip()
                if len(cleaned) > 10 and len(cleaned) < 100:
                    return cleaned
        
        # Fallback incident name
        return "Suspicious Network Activity Detected"
    
    def _extract_criticality(self, ai_content: str) -> str:
        """Extract criticality level from AI response"""
        content_lower = ai_content.lower()
        
        if any(keyword in content_lower for keyword in ['high', 'critical', 'severe', 'immediate']):
            return "High"
        elif any(keyword in content_lower for keyword in ['medium', 'moderate', 'elevated']):
            return "Medium"
        else:
            return "Low"

class SOCAutomation:
    def __init__(self):
        self.packet_analyzer = PacketAnalyzer()
        self.threat_detector = ThreatDetector()
        self.ai_analyzer = AIAnalyzer(GROQ_API_KEY)
        self.email_notifier = EmailNotifier(SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD)
        self.alerts_db = {}  # In-memory storage for alerts
        
    async def process_packet_capture(self, pcap_file: str) -> AnalysisResult:
        """Main processing pipeline for packet capture analysis"""
        try:
            # Step 1: Analyze packets
            print(f"Analyzing packet capture: {pcap_file}")
            packet_analyses = self.packet_analyzer.analyze_packet_capture(pcap_file)
            
            if not packet_analyses:
                return AnalysisResult(
                    analysis_id=str(uuid.uuid4()),
                    packet_count=0,
                    suspicious_packets=0,
                    alerts_generated=0,
                    status="No packets to analyze",
                    evidence_files=[],
                    notifications_sent={}
                )
            
            # Step 2: Detect threats
            print(f"Detecting threats in {len(packet_analyses)} packets...")
            threats = self.threat_detector.detect_threats(packet_analyses)
            
            # Step 3: Generate alert if threats found
            alerts_generated = 0
            evidence_files = []
            notifications_sent = {"email": False}
            
            if threats:
                print(f"Found {len(threats)} threats, generating alert...")
                alert = await self.ai_analyzer.generate_alert(threats, packet_analyses)
                
                # Step 4: Save evidence
                evidence_file_path = await self._save_evidence(alert, packet_analyses, threats)
                evidence_files.append(evidence_file_path)
                
                # Step 5: Send email notification
                if await self.email_notifier.send_alert_notification(alert, evidence_file_path):
                    alert.email_sent = True
                    notifications_sent["email"] = True
                
                # Step 6: Store alert
                self.alerts_db[alert.incident_id] = alert
                alerts_generated = 1
                
                print(f"Alert generated: {alert.incident_id} - {alert.incident_name}")
            
            analysis_id = str(uuid.uuid4())
            return AnalysisResult(
                analysis_id=analysis_id,
                packet_count=len(packet_analyses),
                suspicious_packets=len([p for p in packet_analyses if self._is_suspicious_packet(p)]),
                alerts_generated=alerts_generated,
                status="Analysis completed successfully",
                evidence_files=evidence_files,
                notifications_sent=notifications_sent
            )
            
        except Exception as e:
            print(f"Error processing packet capture: {e}")
            return AnalysisResult(
                analysis_id=str(uuid.uuid4()),
                packet_count=0,
                suspicious_packets=0,
                alerts_generated=0,
                status=f"Error: {str(e)}",
                evidence_files=[],
                notifications_sent={}
            )
            
    def _is_suspicious_packet(self, packet: PacketAnalysis) -> bool:
        """Check if a packet is suspicious"""
        suspicious_indicators = [
            packet.dst_port in SUSPICIOUS_PORTS if packet.dst_port else False,
            any(domain in (packet.dns_query or "") for domain in SUSPICIOUS_DOMAINS),
            any(domain in (packet.http_host or "") for domain in SUSPICIOUS_DOMAINS),
            packet.payload_size > 1000000,  # Large payload
        ]
        return any(suspicious_indicators)
    
    async def _save_evidence(self, alert: SecurityAlert, packet_analyses: List[PacketAnalysis], 
                           threats: List[ThreatIndicator]) -> str:
        """Save evidence files for the alert"""
        
        # Save packet analysis evidence
        evidence_file_path = EVIDENCE_DIR / alert.evidence_file
        
        # Convert packet analyses to DataFrame for CSV export
        packet_data = []
        for analysis in packet_analyses:
            packet_data.append({
                "timestamp": datetime.fromtimestamp(analysis.timestamp, timezone.utc).isoformat(),
                "src_ip": analysis.src_ip,
                "dst_ip": analysis.dst_ip,
                "src_port": analysis.src_port,
                "dst_port": analysis.dst_port,
                "protocol": analysis.protocol,
                "payload_size": analysis.payload_size,
                "dns_query": analysis.dns_query,
                "http_host": analysis.http_host,
                "http_uri": analysis.http_uri,
                "flags": analysis.flags,
                "is_suspicious": self._is_suspicious_packet(analysis)
            })
        
        # Save to CSV
        df = pd.DataFrame(packet_data)
        df.to_csv(evidence_file_path, index=False)
        
        # Save threat indicators to separate file
        threat_file_path = EVIDENCE_DIR / f"threats_{alert.incident_id}.json"
        threat_data = []
        for threat in threats:
            threat_data.append({
                "type": threat.indicator_type,
                "value": threat.value,
                "confidence": threat.confidence,
                "description": threat.description
            })
        
        with open(threat_file_path, 'w') as f:
            json.dump(threat_data, f, indent=2)
        
        # Save alert metadata
        alert_file_path = ALERTS_DIR / f"alert_{alert.incident_id}.json"
        alert_data = {
            "incident_id": alert.incident_id,
            "incident_name": alert.incident_name,
            "criticality": alert.criticality,
            "timestamp": alert.timestamp.isoformat(),
            "key_findings": alert.key_findings,
            "ai_recommendation": alert.ai_recommendation,
            "evidence_file": alert.evidence_file,
            "affected_hosts": alert.affected_hosts,
            "c2_indicators": alert.c2_indicators,
            "email_sent": alert.email_sent,
            "threat_count": len(threats),
            "packet_count": len(packet_analyses)
        }
        
        with open(alert_file_path, 'w') as f:
            json.dump(alert_data, f, indent=2)
        
        print(f"Evidence saved: {evidence_file_path}")
        print(f"Threats saved: {threat_file_path}")
        print(f"Alert metadata saved: {alert_file_path}")
        
        return str(evidence_file_path)

# Initialize SOC Automation system
soc_automation = SOCAutomation()

# API Endpoints
@app.post("/analyze/upload", response_model=AnalysisResult)
async def upload_and_analyze_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Upload and analyze PCAP file"""
    if not file.filename.endswith(('.pcap', '.pcapng', '.cap')):
        raise HTTPException(status_code=400, detail="Invalid file format. Please upload a PCAP file.")
    
    # Save uploaded file
    file_path = STORAGE_DIR / f"upload_{uuid.uuid4()}_{file.filename}"
    
    try:
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Process in background
        result = await soc_automation.process_packet_capture(str(file_path))
        
        # Clean up uploaded file
        background_tasks.add_task(os.unlink, file_path)
        
        return result
        
    except Exception as e:
        # Clean up on error
        if file_path.exists():
            os.unlink(file_path)
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

@app.post("/analyze/path", response_model=AnalysisResult)
async def analyze_pcap_path(pcap_path: str):
    """Analyze PCAP file from server path"""
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail="PCAP file not found")
    
    if not pcap_path.endswith(('.pcap', '.pcapng', '.cap')):
        raise HTTPException(status_code=400, detail="Invalid file format")
    
    try:
        result = await soc_automation.process_packet_capture(pcap_path)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

@app.get("/alerts", response_model=List[SecurityAlert])
async def get_all_alerts():
    """Get all security alerts"""
    return list(soc_automation.alerts_db.values())

@app.get("/alerts/{incident_id}", response_model=SecurityAlert)
async def get_alert(incident_id: str):
    """Get specific security alert"""
    if incident_id not in soc_automation.alerts_db:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return soc_automation.alerts_db[incident_id]

@app.put("/alerts/{incident_id}/approve")
async def approve_alert(incident_id: str):
    """Approve a security alert"""
    if incident_id not in soc_automation.alerts_db:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert = soc_automation.alerts_db[incident_id]
    alert.human_approved = True
    alert.approval_timestamp = datetime.now(timezone.utc)
    
    # Update alert file
    alert_file_path = ALERTS_DIR / f"alert_{incident_id}.json"
    if alert_file_path.exists():
        with open(alert_file_path, 'r') as f:
            alert_data = json.load(f)
        
        alert_data['human_approved'] = True
        alert_data['approval_timestamp'] = alert.approval_timestamp.isoformat()
        
        with open(alert_file_path, 'w') as f:
            json.dump(alert_data, f, indent=2)
    
    return {"message": f"Alert {incident_id} approved successfully"}

@app.put("/alerts/{incident_id}/reject")
async def reject_alert(incident_id: str, reason: str = ""):
    """Reject a security alert"""
    if incident_id not in soc_automation.alerts_db:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert = soc_automation.alerts_db[incident_id]
    alert.human_approved = False
    alert.approval_timestamp = datetime.now(timezone.utc)
    
    # Update alert file
    alert_file_path = ALERTS_DIR / f"alert_{incident_id}.json"
    if alert_file_path.exists():
        with open(alert_file_path, 'r') as f:
            alert_data = json.load(f)
        
        alert_data['human_approved'] = False
        alert_data['approval_timestamp'] = alert.approval_timestamp.isoformat()
        alert_data['rejection_reason'] = reason
        
        with open(alert_file_path, 'w') as f:
            json.dump(alert_data, f, indent=2)
    
    return {"message": f"Alert {incident_id} rejected successfully"}

@app.get("/evidence/{incident_id}")
async def download_evidence(incident_id: str):
    """Download evidence file for an alert"""
    if incident_id not in soc_automation.alerts_db:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert = soc_automation.alerts_db[incident_id]
    evidence_file_path = EVIDENCE_DIR / alert.evidence_file
    
    if not evidence_file_path.exists():
        raise HTTPException(status_code=404, detail="Evidence file not found")
    
    return FileResponse(
        path=str(evidence_file_path),
        filename=alert.evidence_file,
        media_type='text/csv'
    )

@app.get("/threats/{incident_id}")
async def download_threats(incident_id: str):
    """Download threat indicators file for an alert"""
    threat_file_path = EVIDENCE_DIR / f"threats_{incident_id}.json"
    
    if not threat_file_path.exists():
        raise HTTPException(status_code=404, detail="Threat indicators file not found")
    
    return FileResponse(
        path=str(threat_file_path),
        filename=f"threats_{incident_id}.json",
        media_type='application/json'
    )

@app.get("/stats")
async def get_statistics():
    """Get system statistics"""
    alerts = list(soc_automation.alerts_db.values())
    
    stats = {
        "total_alerts": len(alerts),
        "high_priority": len([a for a in alerts if a.criticality == "High"]),
        "medium_priority": len([a for a in alerts if a.criticality == "Medium"]),
        "low_priority": len([a for a in alerts if a.criticality == "Low"]),
        "approved_alerts": len([a for a in alerts if a.human_approved is True]),
        "rejected_alerts": len([a for a in alerts if a.human_approved is False]),
        "pending_approval": len([a for a in alerts if a.human_approved is None]),
        "emails_sent": len([a for a in alerts if a.email_sent]),
        "recent_alerts": len([a for a in alerts if (datetime.now(timezone.utc) - a.timestamp).days < 7])
    }
    
    return stats

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0",
        "storage_dir": str(STORAGE_DIR),
        "evidence_dir": str(EVIDENCE_DIR),
        "alerts_dir": str(ALERTS_DIR)
    }

# Add CORS middleware if needed
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting SOC Packet Analysis Automation System v2.0.0")
    print(f"📁 Storage Directory: {STORAGE_DIR}")
    print(f"📊 Evidence Directory: {EVIDENCE_DIR}")
    print(f"🚨 Alerts Directory: {ALERTS_DIR}")
    print(f"📧 Email Notifications: {SMTP_SERVER}:{SMTP_PORT}")
    print("=" * 60)
    
    uvicorn.run(
        "main:app",  # Adjust if filename is different
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )
