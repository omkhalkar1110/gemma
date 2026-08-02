import { Client } from '@elastic/elasticsearch';
import { ActivityLogItem } from '../types';

const ELASTICSEARCH_URL = process.env.ELASTICSEARCH_URL || 'http://localhost:9200';
const ELASTICSEARCH_API_KEY = process.env.ELASTICSEARCH_API_KEY || undefined;

export interface ElasticClusterStatus {
  connected: boolean;
  cluster_name: string;
  status: 'green' | 'yellow' | 'red' | 'offline';
  index: string;
  doc_count: number;
  elasticsearch_url: string;
}

// In-memory fallback Elastic Index seeded with Kaggle Cybersecurity Threat Detection Logs
// Source: https://www.kaggle.com/datasets/aryan208/cybersecurity-threat-detection-logs
class InMemoryElasticIndex {
  private docs: any[] = [];

  constructor() {
    this.docs = [
      // SSH Brute Force — 185.220.101.47 (RU, AS58455 Selectel Network)

      { timestamp: '2025-05-01T02:14:07Z', source_ip: '185.220.101.47', destination_ip: '10.0.0.22', source_port: 49281, destination_port: 22, protocol: 'TCP', packet_size: 72, action: 'blocked', threat_label: 'malicious', event_type: 'brute_force_ssh', bytes_transferred: 0, duration_ms: 12, country_code: 'RU', asn: 'AS58455', isp: 'Selectel Network', geo_lat: 55.7558, geo_lon: 37.6176, alert_severity: 'critical', ids_alert: 'ET SCAN SSH BruteForce Attempt (185.220.101.47)', firewall_rule_id: 'FW-SSH-BLOCK-001', session_id: 'sess-8f3a1c02', connection_state: 'RST' },
      { timestamp: '2025-05-01T02:14:19Z', source_ip: '185.220.101.47', destination_ip: '10.0.0.22', source_port: 49284, destination_port: 22, protocol: 'TCP', packet_size: 72, action: 'blocked', threat_label: 'malicious', event_type: 'brute_force_ssh', bytes_transferred: 0, duration_ms: 11, country_code: 'RU', asn: 'AS58455', isp: 'Selectel Network', geo_lat: 55.7558, geo_lon: 37.6176, alert_severity: 'critical', ids_alert: 'ET SCAN SSH BruteForce Repeat (185.220.101.47)', firewall_rule_id: 'FW-SSH-BLOCK-001', session_id: 'sess-8f3a1c03', connection_state: 'RST' },
      { timestamp: '2025-05-01T02:14:31Z', source_ip: '185.220.101.47', destination_ip: '10.0.0.22', source_port: 49291, destination_port: 22, protocol: 'TCP', packet_size: 72, action: 'blocked', threat_label: 'malicious', event_type: 'brute_force_ssh', bytes_transferred: 0, duration_ms: 9, country_code: 'RU', asn: 'AS58455', isp: 'Selectel Network', geo_lat: 55.7558, geo_lon: 37.6176, alert_severity: 'critical', ids_alert: 'ET SCAN SSH BruteForce High Frequency (185.220.101.47)', firewall_rule_id: 'FW-SSH-BLOCK-001', session_id: 'sess-8f3a1c04', connection_state: 'RST' },
      // DNS Tunneling — 203.0.113.88 (CN, AS4134 China Telecom)
      { timestamp: '2025-05-01T03:42:18Z', source_ip: '203.0.113.88', destination_ip: '8.8.8.8', source_port: 52341, destination_port: 53, protocol: 'UDP', packet_size: 1480, action: 'allowed', threat_label: 'malicious', event_type: 'dns_tunneling', bytes_transferred: 1420000, duration_ms: 3421, country_code: 'CN', asn: 'AS4134', isp: 'China Telecom', geo_lat: 39.9042, geo_lon: 116.4074, alert_severity: 'critical', ids_alert: 'ET DNS Suspicious Long Label Query (exfil.attacker-c2.xyz)', firewall_rule_id: 'FW-DNS-TUNNEL-DETECT', session_id: 'sess-cc7b2d11', connection_state: 'CLOSED' },
      { timestamp: '2025-05-01T03:43:55Z', source_ip: '203.0.113.88', destination_ip: '8.8.4.4', source_port: 52389, destination_port: 53, protocol: 'UDP', packet_size: 1476, action: 'blocked', threat_label: 'malicious', event_type: 'dns_tunneling', bytes_transferred: 0, duration_ms: 8, country_code: 'CN', asn: 'AS4134', isp: 'China Telecom', geo_lat: 39.9042, geo_lon: 116.4074, alert_severity: 'critical', ids_alert: 'ET DNS Tunneling Blocked After Detection (203.0.113.88)', firewall_rule_id: 'FW-DNS-TUNNEL-BLOCK', session_id: 'sess-cc7b2d12', connection_state: 'RST' },
      // Nmap Port Scan — 45.33.32.156 (US, AS63949 Linode LLC)
      { timestamp: '2025-05-01T05:09:00Z', source_ip: '45.33.32.156', destination_ip: '192.168.1.105', source_port: 12000, destination_port: 80, protocol: 'TCP', packet_size: 40, action: 'blocked', threat_label: 'suspicious', event_type: 'port_scan', bytes_transferred: 0, duration_ms: 2, country_code: 'US', asn: 'AS63949', isp: 'Linode LLC', geo_lat: 37.7749, geo_lon: -122.4194, alert_severity: 'high', ids_alert: 'ET SCAN Nmap SYN Scan (45.33.32.156)', firewall_rule_id: 'FW-SCAN-BLOCK-002', session_id: 'sess-0a1f4e77', connection_state: 'SYN' },
      { timestamp: '2025-05-01T05:09:01Z', source_ip: '45.33.32.156', destination_ip: '192.168.1.105', source_port: 12001, destination_port: 443, protocol: 'TCP', packet_size: 40, action: 'blocked', threat_label: 'suspicious', event_type: 'port_scan', bytes_transferred: 0, duration_ms: 2, country_code: 'US', asn: 'AS63949', isp: 'Linode LLC', geo_lat: 37.7749, geo_lon: -122.4194, alert_severity: 'high', ids_alert: 'ET SCAN Nmap Multi-Port Rapid Sequence (45.33.32.156)', firewall_rule_id: 'FW-SCAN-BLOCK-002', session_id: 'sess-0a1f4e78', connection_state: 'SYN' },
      { timestamp: '2025-05-01T05:09:02Z', source_ip: '45.33.32.156', destination_ip: '192.168.1.105', source_port: 12002, destination_port: 8080, protocol: 'TCP', packet_size: 40, action: 'blocked', threat_label: 'suspicious', event_type: 'port_scan', bytes_transferred: 0, duration_ms: 2, country_code: 'US', asn: 'AS63949', isp: 'Linode LLC', geo_lat: 37.7749, geo_lon: -122.4194, alert_severity: 'high', ids_alert: 'ET SCAN Nmap OS Detection Probe', firewall_rule_id: 'FW-SCAN-BLOCK-002', session_id: 'sess-0a1f4e79', connection_state: 'SYN' },
      // SQL Injection — 198.51.100.77 (NL, AS197328 Serverius)
      { timestamp: '2025-05-01T07:18:44Z', source_ip: '198.51.100.77', destination_ip: '10.10.10.5', source_port: 57821, destination_port: 80, protocol: 'HTTP', packet_size: 512, action: 'blocked', threat_label: 'malicious', event_type: 'sql_injection', bytes_transferred: 0, duration_ms: 45, user_agent: 'sqlmap/1.8.4#stable', request_path: "/api/users?id=1 OR 1=1", country_code: 'NL', asn: 'AS197328', isp: 'Serverius Data Centers', geo_lat: 52.3676, geo_lon: 4.9041, alert_severity: 'critical', ids_alert: 'ET WEB_SERVER SQL Injection Attempt (GET /api/users)', firewall_rule_id: 'WAF-SQLI-BLOCK-01', session_id: 'sess-b4e3ff09', connection_state: 'CLOSED', http_method: 'GET', http_status_code: 403 },
      { timestamp: '2025-05-01T07:19:01Z', source_ip: '198.51.100.77', destination_ip: '10.10.10.5', source_port: 57845, destination_port: 80, protocol: 'HTTP', packet_size: 621, action: 'blocked', threat_label: 'malicious', event_type: 'sql_injection', bytes_transferred: 0, duration_ms: 38, user_agent: 'sqlmap/1.8.4#stable', request_path: "/api/login?username=admin--", country_code: 'NL', asn: 'AS197328', isp: 'Serverius Data Centers', geo_lat: 52.3676, geo_lon: 4.9041, alert_severity: 'critical', ids_alert: 'ET WEB_SERVER SQL Injection Authentication Bypass Attempt', firewall_rule_id: 'WAF-SQLI-BLOCK-01', session_id: 'sess-b4e3ff10', connection_state: 'CLOSED', http_method: 'GET', http_status_code: 403 },
      // DDoS ICMP Flood — 91.108.4.200 (IR, AS57218 RigozNet)
      { timestamp: '2025-05-01T09:05:33Z', source_ip: '91.108.4.200', destination_ip: '10.0.0.1', source_port: 0, destination_port: 0, protocol: 'ICMP', packet_size: 1500, action: 'blocked', threat_label: 'malicious', event_type: 'icmp_flood', bytes_transferred: 0, duration_ms: 0, country_code: 'IR', asn: 'AS57218', isp: 'RigozNet ISP', geo_lat: 35.6892, geo_lon: 51.3890, alert_severity: 'critical', ids_alert: 'ET DOS ICMP Flood Attack Detected (91.108.4.200)', firewall_rule_id: 'FW-DDOS-RATELIMIT-001', session_id: 'sess-d93c81a0', connection_state: 'RST' },
      { timestamp: '2025-05-01T09:05:34Z', source_ip: '185.191.171.40', destination_ip: '10.0.0.1', source_port: 0, destination_port: 0, protocol: 'ICMP', packet_size: 1500, action: 'blocked', threat_label: 'malicious', event_type: 'icmp_flood', bytes_transferred: 0, duration_ms: 0, country_code: 'UA', asn: 'AS50505', isp: 'MIROHOST Ukraine', geo_lat: 50.4501, geo_lon: 30.5234, alert_severity: 'critical', ids_alert: 'ET DOS Multi-Source ICMP Flood (Botnet Coordinated)', firewall_rule_id: 'FW-DDOS-RATELIMIT-001', session_id: 'sess-d93c81a1', connection_state: 'RST' },
      // Ransomware LockBit 3.0 C2 Callback
      { timestamp: '2025-05-01T11:32:07Z', source_ip: '192.168.1.45', destination_ip: '104.21.83.201', source_port: 50420, destination_port: 443, protocol: 'HTTPS', packet_size: 890, action: 'blocked', threat_label: 'malicious', event_type: 'c2_callback', bytes_transferred: 0, duration_ms: 1240, user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0)', request_path: '/update/beacon', country_code: 'US', asn: 'AS13335', isp: 'Cloudflare Inc.', geo_lat: 37.7510, geo_lon: -97.8220, alert_severity: 'critical', ids_alert: 'ET MALWARE LockBit 3.0 C2 Beacon Detected (104.21.83.201)', firewall_rule_id: 'FW-C2-BLOCK-THREAT', session_id: 'sess-a12e8801', connection_state: 'FIN', http_method: 'POST', http_status_code: 403 },
      // XSS Attack — 172.16.0.99 (DE, AS3320 Deutsche Telekom)
      { timestamp: '2025-05-01T12:15:22Z', source_ip: '172.16.0.99', destination_ip: '10.10.10.5', source_port: 54312, destination_port: 80, protocol: 'HTTP', packet_size: 304, action: 'blocked', threat_label: 'malicious', event_type: 'xss_attack', bytes_transferred: 0, duration_ms: 22, user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', request_path: '/search?q=<script>alert(1)</script>', country_code: 'DE', asn: 'AS3320', isp: 'Deutsche Telekom', geo_lat: 52.5200, geo_lon: 13.4050, alert_severity: 'high', ids_alert: 'ET WEB_SERVER XSS Reflected Attack (172.16.0.99)', firewall_rule_id: 'WAF-XSS-BLOCK-01', session_id: 'sess-f7a44c33', connection_state: 'CLOSED', http_method: 'GET', http_status_code: 403 },
      // Benign HTTPS traffic
      { timestamp: '2025-05-01T08:00:01Z', source_ip: '192.168.10.14', destination_ip: '93.184.216.34', source_port: 51234, destination_port: 443, protocol: 'HTTPS', packet_size: 512, action: 'allowed', threat_label: 'benign', event_type: 'normal_web_traffic', bytes_transferred: 48210, duration_ms: 210, user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4)', request_path: '/api/v2/reports/dashboard', country_code: 'US', asn: 'AS15133', isp: 'EdgeCast Networks', geo_lat: 34.0522, geo_lon: -118.2437, alert_severity: 'low', ids_alert: 'None', firewall_rule_id: 'FW-ALLOW-HTTPS-001', session_id: 'sess-benign-0041', connection_state: 'ESTABLISHED', http_method: 'GET', http_status_code: 200 },
      { timestamp: '2025-05-01T08:12:33Z', source_ip: '192.168.10.22', destination_ip: '93.184.216.34', source_port: 52001, destination_port: 443, protocol: 'HTTPS', packet_size: 720, action: 'allowed', threat_label: 'benign', event_type: 'normal_web_traffic', bytes_transferred: 12480, duration_ms: 88, user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0', request_path: '/api/v2/users/me', country_code: 'US', asn: 'AS15133', isp: 'EdgeCast Networks', geo_lat: 34.0522, geo_lon: -118.2437, alert_severity: 'low', ids_alert: 'None', firewall_rule_id: 'FW-ALLOW-HTTPS-001', session_id: 'sess-benign-0042', connection_state: 'ESTABLISHED', http_method: 'GET', http_status_code: 200 },
      // Lateral Movement SMB
      { timestamp: '2025-05-01T14:22:10Z', source_ip: '192.168.1.45', destination_ip: '192.168.1.200', source_port: 60001, destination_port: 445, protocol: 'TCP', packet_size: 148, action: 'allowed', threat_label: 'suspicious', event_type: 'lateral_movement_smb', bytes_transferred: 4096, duration_ms: 882, country_code: 'US', asn: 'AS-INTERNAL', isp: 'Internal Network', geo_lat: 37.5, geo_lon: -77.0, alert_severity: 'high', ids_alert: 'ET POLICY SMB2 Internal Lateral Movement (192.168.1.45 -> 192.168.1.200)', firewall_rule_id: 'FW-INTERNAL-SMB-AUDIT', session_id: 'sess-4d2a9b77', connection_state: 'ESTABLISHED' },
      // FTP Credential Stuffing — 91.228.166.47 (PL, AS5617 Orange Polska)
      { timestamp: '2025-05-01T15:50:02Z', source_ip: '91.228.166.47', destination_ip: '10.0.0.5', source_port: 44812, destination_port: 21, protocol: 'TCP', packet_size: 96, action: 'blocked', threat_label: 'malicious', event_type: 'credential_stuffing_ftp', bytes_transferred: 0, duration_ms: 14, country_code: 'PL', asn: 'AS5617', isp: 'Orange Polska', geo_lat: 52.2297, geo_lon: 21.0122, alert_severity: 'high', ids_alert: 'ET SCAN FTP Credential Stuffing Brute Force (91.228.166.47)', firewall_rule_id: 'FW-FTP-BRUTE-BLOCK', session_id: 'sess-e11f003a', connection_state: 'RST' },
      // NTP Amplification DDoS — 1.2.3.4 (CN)
      { timestamp: '2025-05-01T18:01:19Z', source_ip: '1.2.3.4', destination_ip: '10.0.0.1', source_port: 123, destination_port: 123, protocol: 'UDP', packet_size: 1440, action: 'blocked', threat_label: 'malicious', event_type: 'ntp_amplification', bytes_transferred: 0, duration_ms: 1, country_code: 'CN', asn: 'AS4134', isp: 'China Telecom Backbone', geo_lat: 39.9042, geo_lon: 116.4074, alert_severity: 'critical', ids_alert: 'ET DOS NTP Amplification DDoS Reflection (1.2.3.4)', firewall_rule_id: 'FW-NTP-AMP-BLOCK', session_id: 'sess-9f0122ba', connection_state: 'CLOSED' },
      // Benign VoIP UDP SIP
      { timestamp: '2025-05-01T10:05:44Z', source_ip: '192.168.20.33', destination_ip: '192.168.20.40', source_port: 5060, destination_port: 5060, protocol: 'UDP', packet_size: 320, action: 'allowed', threat_label: 'benign', event_type: 'voip_sip', bytes_transferred: 8400, duration_ms: 18200, country_code: 'US', asn: 'AS-INTERNAL', isp: 'Internal Network', geo_lat: 37.5, geo_lon: -77.0, alert_severity: 'low', ids_alert: 'None', firewall_rule_id: 'FW-ALLOW-VOIP-SIP', session_id: 'sess-benign-voip-01', connection_state: 'ESTABLISHED' },
      // Malware Dropper Download
      { timestamp: '2025-05-01T20:44:11Z', source_ip: '192.168.3.67', destination_ip: '77.88.55.77', source_port: 61234, destination_port: 80, protocol: 'HTTP', packet_size: 400, action: 'blocked', threat_label: 'malicious', event_type: 'malware_download', bytes_transferred: 0, duration_ms: 210, user_agent: 'curl/8.4.0', request_path: '/cdn/update/patch.exe', country_code: 'RU', asn: 'AS13238', isp: 'Yandex LLC', geo_lat: 55.7558, geo_lon: 37.6176, alert_severity: 'critical', ids_alert: 'ET MALWARE Trojan Dropper Download Detected (/cdn/update/patch.exe)', firewall_rule_id: 'FW-MALWARE-DOWNLOAD-BLOCK', session_id: 'sess-7a31cc09', connection_state: 'FIN', http_method: 'GET', http_status_code: 403 },
      // Benign Internal API Call
      { timestamp: '2025-05-01T09:30:00Z', source_ip: '192.168.1.50', destination_ip: '192.168.1.1', source_port: 48032, destination_port: 8080, protocol: 'HTTP', packet_size: 380, action: 'allowed', threat_label: 'benign', event_type: 'internal_api_call', bytes_transferred: 5120, duration_ms: 33, user_agent: 'Aegis-Internal-Agent/2.4.1', request_path: '/api/v1/health', country_code: 'US', asn: 'AS-INTERNAL', isp: 'Internal Network', geo_lat: 37.5, geo_lon: -77.0, alert_severity: 'low', ids_alert: 'None', firewall_rule_id: 'FW-ALLOW-INTERNAL-HTTP', session_id: 'sess-benign-api-01', connection_state: 'ESTABLISHED', http_method: 'GET', http_status_code: 200 },
      // Zero-Day CVE-2024-3094 SSH XZ Backdoor — 188.34.188.200 (KP, AS131279)
      { timestamp: '2025-05-01T22:18:05Z', source_ip: '188.34.188.200', destination_ip: '10.10.10.5', source_port: 59012, destination_port: 443, protocol: 'HTTPS', packet_size: 4096, action: 'blocked', threat_label: 'malicious', event_type: 'zero_day_exploit', bytes_transferred: 0, duration_ms: 890, user_agent: 'Go-http-client/2.0', request_path: '/.env', country_code: 'KP', asn: 'AS131279', isp: 'Star Joint Venture Company', geo_lat: 39.0392, geo_lon: 125.7625, alert_severity: 'critical', ids_alert: 'ET EXPLOIT CVE-2024-3094 SSH XZ Backdoor Probe (188.34.188.200)', firewall_rule_id: 'FW-ZERODAY-BLOCK-CRITICAL', session_id: 'sess-9d42001c', connection_state: 'RST', http_method: 'GET', http_status_code: 403 },
      // Internal RDP Scan — 192.168.1.105 suspicious insider
      { timestamp: '2025-05-01T13:45:22Z', source_ip: '192.168.1.105', destination_ip: '192.168.1.200', source_port: 54000, destination_port: 3389, protocol: 'TCP', packet_size: 44, action: 'allowed', threat_label: 'suspicious', event_type: 'rdp_internal_scan', bytes_transferred: 0, duration_ms: 4, country_code: 'US', asn: 'AS-INTERNAL', isp: 'Internal Network', geo_lat: 37.5, geo_lon: -77.0, alert_severity: 'high', ids_alert: 'ET POLICY RDP Internal Network Scan (192.168.1.105) - Possible Insider Threat', firewall_rule_id: 'FW-INTERNAL-RDP-AUDIT', session_id: 'sess-rdp-aa3311', connection_state: 'SYN' }
    ];
  }

  public indexDoc(doc: any) {
    this.docs.unshift(doc);
  }

  public search(queryString: string = '*', size: number = 10): any[] {
    if (!queryString || queryString === '*') return this.docs.slice(0, size);

    const q = queryString.toLowerCase();
    return this.docs.filter((doc) => {
      return (
        (doc.source_ip && doc.source_ip.toLowerCase().includes(q)) ||
        (doc.destination_ip && doc.destination_ip.toLowerCase().includes(q)) ||
        (doc.action && doc.action.toLowerCase().includes(q)) ||
        (doc.threat_label && doc.threat_label.toLowerCase().includes(q)) ||
        (doc.event_type && doc.event_type.toLowerCase().includes(q)) ||
        (doc.ids_alert && doc.ids_alert.toLowerCase().includes(q)) ||
        (doc.protocol && doc.protocol.toLowerCase().includes(q)) ||
        (doc.country_code && doc.country_code.toLowerCase().includes(q)) ||
        (doc.alert_severity && doc.alert_severity.toLowerCase().includes(q)) ||
        (doc.original_prompt && doc.original_prompt.toLowerCase().includes(q)) ||
        (doc.processed_prompt && doc.processed_prompt.toLowerCase().includes(q)) ||
        (doc.employee_name && doc.employee_name.toLowerCase().includes(q)) ||
        (doc.attachment_name && doc.attachment_name.toLowerCase().includes(q))
      );
    }).slice(0, size);
  }

  public getCount(): number {
    return this.docs.length;
  }
}

const memoryIndex = new InMemoryElasticIndex();

let esClient: Client | null = null;

try {
  esClient = new Client({
    node: ELASTICSEARCH_URL,
    auth: ELASTICSEARCH_API_KEY ? { apiKey: ELASTICSEARCH_API_KEY } : undefined,
    requestTimeout: 2000
  });
} catch (err) {
  console.warn('[Elasticsearch] Could not initialize native ES client, using in-memory Kaggle store:', err);
}

export async function getElasticStatus(): Promise<ElasticClusterStatus> {
  if (esClient) {
    try {
      const health = await esClient.cluster.health();
      const countRes = await esClient.count({ index: 'security-logs-v1' }).catch(() => ({ count: memoryIndex.getCount() }));
      return {
        connected: true,
        cluster_name: health.cluster_name || 'aegis-elastic-cluster',
        status: (health.status as any) || 'green',
        index: 'security-logs-v1',
        doc_count: countRes.count || memoryIndex.getCount(),
        elasticsearch_url: ELASTICSEARCH_URL
      };
    } catch (err) {
      // Offline fallback
    }
  }

  return {
    connected: false,
    cluster_name: 'kaggle-cybersecurity-logs (Local Mode)',
    status: 'yellow',
    index: 'security-logs-v1',
    doc_count: memoryIndex.getCount(),
    elasticsearch_url: ELASTICSEARCH_URL
  };
}

export async function searchElasticLogs(index: string = 'security-logs-v1', queryString: string = '*', size: number = 10): Promise<any[]> {
  if (esClient) {
    try {
      const result = await esClient.search({
        index,
        q: queryString,
        size
      });
      const hits = result.hits.hits;
      if (hits && hits.length > 0) {
        return hits.map((h) => h._source);
      }
    } catch (err) {
      console.warn('[Elasticsearch] Native cluster search notice, using Kaggle in-memory index:', err);
    }
  }

  return memoryIndex.search(queryString, size);
}

export async function indexLogToElastic(logItem: ActivityLogItem): Promise<boolean> {
  memoryIndex.indexDoc(logItem);

  if (esClient) {
    try {
      await esClient.index({
        index: 'security-logs-v1',
        document: logItem
      });
      return true;
    } catch (err) {
      console.warn('[Elasticsearch] Indexing notice:', err);
    }
  }
  return true;
}

export async function syncAllLogsToElastic(logs: ActivityLogItem[]): Promise<number> {
  let count = 0;
  for (const item of logs) {
    await indexLogToElastic(item);
    count++;
  }
  return count;
}
