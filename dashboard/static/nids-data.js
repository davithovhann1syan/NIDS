'use strict';
// NIDS Data Engine — plain JS, loaded before JSX files

const NIDS_RULES = [
  { name:"Port Scan (SYN)",              cat:"Reconnaissance", sev:"HIGH",   type:"rate",             mitre:"T1046"     },
  { name:"Port Scan (Distinct Ports)",   cat:"Reconnaissance", sev:"HIGH",   type:"multi_destination", mitre:"T1046"     },
  { name:"Host Discovery Sweep (Distinct IPs)", cat:"Reconnaissance", sev:"HIGH", type:"multi_destination", mitre:"T1018" },
  { name:"Low TTL Probe (Traceroute / Evasion)", cat:"Reconnaissance", sev:"LOW", type:"pattern",        mitre:"T1040"   },
  { name:"TCP SYN with Large Payload",   cat:"Reconnaissance", sev:"MEDIUM", type:"pattern",            mitre:"T1499.002"},
  { name:"ICMP Redirect (Routing Manipulation)", cat:"Infrastructure Attack", sev:"HIGH", type:"pattern", mitre:"T1565" },
  { name:"XMAS Scan",               cat:"Recon",       sev:"MEDIUM",   type:"pattern", mitre:"T1046"     },
  { name:"NULL Scan",               cat:"Recon",       sev:"MEDIUM",   type:"pattern", mitre:"T1046"     },
  { name:"FIN Scan",                cat:"Recon",       sev:"MEDIUM",   type:"pattern", mitre:"T1046"     },
  { name:"ACK Scan",                cat:"Recon",       sev:"LOW",      type:"pattern", mitre:"T1046"     },
  { name:"Ping Sweep",              cat:"Recon",       sev:"LOW",      type:"rate",    mitre:"T1018"     },
  { name:"UDP Port Scan",           cat:"Recon",       sev:"LOW",      type:"rate",    mitre:"T1046"     },
  { name:"OS Fingerprinting",       cat:"Recon",       sev:"MEDIUM",   type:"pattern", mitre:"T1082"     },
  { name:"Slow Scan",               cat:"Recon",       sev:"LOW",      type:"rate",    mitre:"T1046"     },
  { name:"SSH Brute Force",         cat:"Brute Force", sev:"HIGH",     type:"rate",    mitre:"T1110.001" },
  { name:"FTP Brute Force",         cat:"Brute Force", sev:"HIGH",     type:"rate",    mitre:"T1110.001" },
  { name:"RDP Brute Force",         cat:"Brute Force", sev:"HIGH",     type:"rate",    mitre:"T1110.001" },
  { name:"SMB Brute Force",         cat:"Brute Force", sev:"HIGH",     type:"rate",    mitre:"T1110.001" },
  { name:"VNC Brute Force",         cat:"Brute Force", sev:"HIGH",     type:"rate",    mitre:"T1110.001" },
  { name:"MySQL Brute Force",       cat:"Brute Force", sev:"MEDIUM",   type:"rate",    mitre:"T1110.001" },
  { name:"Redis Brute Force",       cat:"Brute Force", sev:"MEDIUM",   type:"rate",    mitre:"T1110.001" },
  { name:"Telnet Brute Force",      cat:"Brute Force", sev:"MEDIUM",   type:"rate",    mitre:"T1110.001" },
  { name:"LDAP Brute Force",        cat:"Brute Force", sev:"MEDIUM",   type:"rate",    mitre:"T1110.001" },
  { name:"EternalBlue (MS17-010)",  cat:"Exploit",     sev:"CRITICAL", type:"pattern", mitre:"T1190"     },
  { name:"BlueKeep",                cat:"Exploit",     sev:"CRITICAL", type:"pattern", mitre:"T1190"     },
  { name:"Log4Shell",               cat:"Exploit",     sev:"CRITICAL", type:"pattern", mitre:"T1190"     },
  { name:"Shellshock",              cat:"Exploit",     sev:"CRITICAL", type:"pattern", mitre:"T1190"     },
  { name:"PrintNightmare",          cat:"Exploit",     sev:"CRITICAL", type:"pattern", mitre:"T1068"     },
  { name:"SQL Injection (HTTP)",    cat:"Exploit",     sev:"HIGH",     type:"pattern", mitre:"T1190"     },
  { name:"PHP Webshell",            cat:"Exploit",     sev:"CRITICAL", type:"pattern", mitre:"T1505.003" },
  { name:"Log4Shell (POST)",        cat:"Exploit",     sev:"CRITICAL", type:"pattern", mitre:"T1190"     },
  { name:"Cobalt Strike Beacon",    cat:"Malware/C2",  sev:"CRITICAL", type:"pattern", mitre:"T1105"     },
  { name:"Metasploit Default",      cat:"Malware/C2",  sev:"HIGH",     type:"pattern", mitre:"T1587.001" },
  { name:"DNS Tunneling",           cat:"Malware/C2",  sev:"HIGH",     type:"rate",    mitre:"T1071.004" },
  { name:"ICMP Tunneling",          cat:"Malware/C2",  sev:"HIGH",     type:"pattern", mitre:"T1048.003" },
  { name:"Reverse Shell Port",      cat:"Malware/C2",  sev:"CRITICAL", type:"pattern", mitre:"T1059"     },
  { name:"Empire C2",               cat:"Malware/C2",  sev:"CRITICAL", type:"pattern", mitre:"T1105"     },
  { name:"IRC Botnet",              cat:"Malware/C2",  sev:"HIGH",     type:"rate",    mitre:"T1571"     },
  { name:"Large Outbound Transfer", cat:"Exfil",       sev:"HIGH",     type:"rate",    mitre:"T1048"     },
  { name:"DNS Exfiltration",        cat:"Exfil",       sev:"HIGH",     type:"rate",    mitre:"T1048.001" },
  { name:"Abnormal TTL",            cat:"Exfil",       sev:"MEDIUM",   type:"pattern", mitre:"T1001"     },
  { name:"High-Freq Small Packets", cat:"Exfil",       sev:"MEDIUM",   type:"rate",    mitre:"T1030"     },
  { name:"Tor Exit Node",           cat:"Policy",      sev:"MEDIUM",   type:"pattern", mitre:"T1090.003" },
  { name:"Crypto Mining",           cat:"Policy",      sev:"MEDIUM",   type:"pattern", mitre:"T1496"     },
  { name:"BitTorrent P2P",          cat:"Policy",      sev:"LOW",      type:"pattern", mitre:"T1048"     },
  { name:"Cleartext Telnet",        cat:"Policy",      sev:"LOW",      type:"pattern", mitre:"T1040"     },
  { name:"Cleartext FTP",           cat:"Policy",      sev:"LOW",      type:"pattern", mitre:"T1040"     },
  { name:"Open Proxy",              cat:"Policy",      sev:"MEDIUM",   type:"pattern", mitre:"T1090"     },
  { name:"Lateral Movement",        cat:"Internal",    sev:"HIGH",     type:"rate",    mitre:"T1021"     },
  { name:"ARP Spoofing",            cat:"Internal",    sev:"HIGH",     type:"pattern", mitre:"T1557.002" },
  { name:"Internal Host Sweep",     cat:"Internal",    sev:"MEDIUM",   type:"rate",    mitre:"T1018"     },
  { name:"SMB Spread",              cat:"Internal",    sev:"HIGH",     type:"rate",    mitre:"T1570"     },
  { name:"RPC Abuse",               cat:"Internal",    sev:"MEDIUM",   type:"pattern", mitre:"T1021.003" },
];

const NIDS_SEV = {
  CRITICAL: { color:"#ff3355", bg:"rgba(255,51,85,0.1)",  glow:"rgba(255,51,85,0.35)",  short:"CRIT" },
  HIGH:     { color:"#ff7c2a", bg:"rgba(255,124,42,0.1)", glow:"rgba(255,124,42,0.3)",  short:"HIGH" },
  MEDIUM:   { color:"#ffbe2e", bg:"rgba(255,190,46,0.1)", glow:"rgba(255,190,46,0.2)",  short:"MED"  },
  LOW:      { color:"#4a8fff", bg:"rgba(74,143,255,0.1)", glow:"rgba(74,143,255,0.2)",  short:"LOW"  },
};

// Covers both simulation categories and backend RULE_CATEGORY values from app.py
const NIDS_CAT_COLOR = {
  "Recon":               "#4a8fff",
  "Brute Force":         "#ff7c2a",
  "Exploit":             "#ff3355",
  "Malware/C2":          "#9b6fff",
  "Exfil":               "#ff6090",
  "Policy":              "#00dfa0",
  "Internal":            "#ffbe2e",
  "Reconnaissance":      "#4a8fff",
  "Denial of Service":   "#ff3355",
  "Suspicious Services": "#ffbe2e",
  "Malware & C2":        "#9b6fff",
  "Lateral Movement":    "#ff7c2a",
  "Exposed Services":    "#ff6090",
  "Exfiltration":        "#ff6090",
  "Infrastructure Attack":"#ff3355",
  "ICS / SCADA":         "#00dfa0",
  "Policy Violation":    "#00dfa0",
  "Other":               "#566880",
};

// rule name → category (for enriching backend alerts that lack a category)
const NIDS_CAT_LOOKUP = {};
NIDS_RULES.forEach(r => { NIDS_CAT_LOOKUP[r.name] = r.cat; });

// rule name → MITRE technique (simulation rules + backend signature names)
const NIDS_MITRE_LOOKUP = {};
NIDS_RULES.forEach(r => { if (r.mitre) NIDS_MITRE_LOOKUP[r.name] = r.mitre; });
Object.assign(NIDS_MITRE_LOOKUP, {
  "Port Scan (SYN)":               "T1046",
  "Slow Port Scan":                "T1046",
  "Null Scan":                     "T1046",
  "Maimon Scan":                   "T1046",
  "ICMP Host Sweep (Ping Sweep)":  "T1018",
  "SSH Brute Force":               "T1110.001",
  "RDP Brute Force":               "T1110.001",
  "FTP Brute Force":               "T1110.001",
  "Telnet Brute Force":            "T1110.001",
  "SMTP Auth Brute Force":         "T1110.003",
  "IMAP Brute Force":              "T1110.001",
  "POP3 Brute Force":              "T1110.001",
  "VNC Brute Force":               "T1110.001",
  "MySQL Brute Force":             "T1110.001",
  "PostgreSQL Brute Force":        "T1110.001",
  "MSSQL Brute Force":             "T1110.001",
  "Kerberos Brute Force (AS-REP Roasting / Password Spray)": "T1558.003",
  "SYN Flood":                     "T1498.001",
  "ICMP Flood":                    "T1498.001",
  "UDP Flood":                     "T1498.001",
  "RST Flood":                     "T1499",
  "ACK Flood":                     "T1498.001",
  "DNS Amplification Attack":      "T1498.002",
  "NTP Amplification Attack":      "T1498.002",
  "Telnet Attempt":                "T1078",
  "FTP Cleartext Login":           "T1078",
  "Known C2 / Backdoor Port":      "T1571",
  "Possible Reverse Shell (High Outbound Port)": "T1059",
  "IRC Traffic (Possible Botnet C2)": "T1571",
  "Tor Default Port":              "T1090.003",
  "DNS over Non-Standard Port (Possible DNS Tunneling)": "T1071.004",
  "Beaconing — High Frequency Outbound (Possible C2 Heartbeat)": "T1102",
  "Cobalt Strike Default Beacon Port": "T1105",
  "Netcat / Bind Shell Default Port":  "T1059",
  "SMB Access (Possible Lateral Movement)": "T1021.002",
  "SMB Sweep (Ransomware Propagation)": "T1570",
  "WinRM Access (Possible Lateral Movement)": "T1021.006",
  "DCOM / RPC Access":             "T1021.003",
  "Remote Registry Access":        "T1012",
  "LDAP Enumeration":              "T1018",
  "Log4Shell Target Port (8080/8443)": "T1190",
  "Redis Exposed (No Auth)":       "T1190",
  "Elasticsearch Exposed":         "T1190",
  "MongoDB Exposed":               "T1190",
  "Docker API Exposed":            "T1610",
  "Kubernetes API Exposed":        "T1610",
  "etcd Exposed":                  "T1552.007",
  "DNS Query Flood (Possible DNS Tunneling)": "T1048.001",
  "ICMP Exfiltration (Large Volume)": "T1048.003",
  "FTP Data Channel (Possible Exfiltration)": "T1048",
  "Modbus Access (ICS Protocol)":  "T0855",
  "DNP3 Access (ICS Protocol)":    "T0855",
  "EtherNet/IP Access (ICS Protocol)": "T0855",
  "BACnet Access (Building Automation)": "T0855",
  "BGP Hijack Attempt":            "T1557",
  "Port Scan (Distinct Ports)":              "T1046",
  "Host Discovery Sweep (Distinct IPs)":     "T1018",
  "Low TTL Probe (Traceroute / Evasion)":    "T1040",
  "ICMP Redirect (Routing Manipulation)":    "T1565",
  "TCP SYN with Large Payload":              "T1499.002",
});

const NIDS_IP_GEO = {
  "185.220.101.47": { lon:4.9,   lat:52.4,  country:"Netherlands" },
  "91.240.118.172": { lon:37.6,  lat:55.7,  country:"Russia"      },
  "45.33.32.156":   { lon:-97,   lat:38.0,  country:"USA"         },
  "192.168.1.104":  { lon:-77.0, lat:38.9,  country:"Internal"    },
  "198.54.117.212": { lon:-74.0, lat:40.7,  country:"USA"         },
  "103.21.244.0":   { lon:103.8, lat:1.3,   country:"Singapore"   },
  "176.58.100.98":  { lon:-0.1,  lat:51.5,  country:"UK"          },
  "10.0.0.45":      { lon:-77.0, lat:38.9,  country:"Internal"    },
  "185.130.5.231":  { lon:10.5,  lat:51.2,  country:"Germany"     },
  "62.210.16.61":   { lon:2.3,   lat:48.9,  country:"France"      },
  "172.67.189.12":  { lon:-118,  lat:34.0,  country:"USA (CDN)"   },
  "95.216.100.76":  { lon:25.7,  lat:60.2,  country:"Finland"     },
  "46.101.64.73":   { lon:4.9,   lat:52.4,  country:"Netherlands" },
  "89.34.111.240":  { lon:32.8,  lat:39.9,  country:"Turkey"      },
  "178.62.52.19":   { lon:-0.1,  lat:51.5,  country:"UK"          },
  "167.99.11.204":  { lon:-73.9, lat:40.7,  country:"USA"         },
  "139.59.50.216":  { lon:77.2,  lat:28.6,  country:"India"       },
  "118.25.6.39":    { lon:121.5, lat:31.2,  country:"China"       },
  "212.227.25.5":   { lon:13.4,  lat:52.5,  country:"Germany"     },
};

// Simplified continent polygons [lon, lat]
const NIDS_CONTINENTS = [
  { id:"na", d:[[-168,72],[-140,70],[-60,47],[-55,46],[-60,10],[-77,7],[-82,9],[-85,12],[-87,16],[-80,25],[-105,22],[-110,23],[-117,32],[-120,37],[-124,47],[-126,50],[-130,55],[-152,60],[-168,57]] },
  { id:"gl", d:[[-73,83],[-15,83],[-18,72],[-43,60],[-65,65],[-70,76]] },
  { id:"sa", d:[[-82,10],[-60,10],[-35,-5],[-38,-12],[-40,-20],[-55,-35],[-70,-55],[-75,-50],[-77,0],[-80,5]] },
  { id:"eu", d:[[-9,36],[5,36],[15,37],[28,37],[30,40],[28,42],[22,46],[15,48],[12,55],[5,58],[-2,58],[-8,44],[-9,38]] },
  { id:"af", d:[[-18,37],[12,37],[37,30],[52,12],[42,10],[42,-2],[36,-18],[33,-35],[18,-35],[10,-35],[-18,15],[-18,30]] },
  { id:"as", d:[[28,42],[38,38],[60,22],[72,20],[80,8],[103,1],[110,-3],[120,5],[130,10],[140,10],[145,38],[130,43],[110,53],[90,60],[70,60],[55,60],[38,55],[28,58]] },
  { id:"ru", d:[[28,58],[55,60],[90,60],[130,43],[145,48],[165,65],[170,70],[90,73],[60,73],[28,70]] },
  { id:"au", d:[[114,-22],[122,-16],[130,-12],[136,-12],[140,-16],[148,-18],[154,-24],[154,-38],[140,-38],[115,-38]] },
  { id:"nz", d:[[166,-46],[175,-37],[178,-38],[175,-44],[168,-46]] },
  { id:"jp", d:[[130,31],[133,34],[138,37],[141,41],[141,45],[138,44],[132,34],[130,31]] },
];

const NIDS_IPS   = Object.keys(NIDS_IP_GEO);
const NIDS_DST   = ["10.0.0.1","10.0.0.2","10.0.0.10","192.168.1.1","192.168.1.5","172.16.0.1","10.0.1.20"];
const NIDS_PORTS = [22,23,21,80,443,445,3389,4444,1337,8080,53,3306,5432,6379,27017,6666,9001,2222];
const NIDS_PROTO = { 6:"TCP", 17:"UDP", 1:"ICMP" };

let _uid = 1000;
function nidsGenAlert(ts) {
  const r     = NIDS_RULES[Math.floor(Math.random()*NIDS_RULES.length)];
  const src   = NIDS_IPS[Math.floor(Math.random()*NIDS_IPS.length)];
  const proto = [6,6,6,17,1][Math.floor(Math.random()*5)];
  return {
    id:          ++_uid,
    timestamp:   ts || new Date(),
    rule:        r.name,
    category:    r.cat,
    severity:    r.sev,
    type:        r.type,
    protocol:    NIDS_PROTO[proto] || "TCP",
    src_ip:      src,
    src_country: NIDS_IP_GEO[src]?.country || "Unknown",
    dst_ip:      NIDS_DST[Math.floor(Math.random()*NIDS_DST.length)],
    dst_port:    NIDS_PORTS[Math.floor(Math.random()*NIDS_PORTS.length)],
    count:        r.type==="rate"||r.type==="multi_destination" ? Math.floor(Math.random()*300)+10 : null,
    ttl:          Math.floor(Math.random()*200)+20,
    length:       Math.floor(Math.random()*1400)+40,
    mitre:        r.mitre || null,
    threat_score: Math.floor(Math.random()*5) * 10,
  };
}

function nidsGenHistory() {
  const out = [];
  const now = Date.now();
  for (let h = 23; h >= 0; h--) {
    const n = Math.floor(Math.random()*22)+3;
    for (let i = 0; i < n; i++)
      out.push(nidsGenAlert(new Date(now - h*3600000 - Math.random()*3600000)));
  }
  return out.sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
}

// Normalize a raw alert (from either the API or simulation) into a consistent shape.
function nidsEnrichAlert(a) {
  return {
    ...a,
    id:          a.id || `${a.timestamp}|${a.rule}`,
    category:    a.category || NIDS_CAT_LOOKUP[a.rule] || "Other",
    src_country: a.src_country || NIDS_IP_GEO[a.src_ip]?.country || "Unknown",
    type:        a.type  || "pattern",
    protocol:    a.protocol || "TCP",
    mitre:       a.mitre || NIDS_MITRE_LOOKUP[a.rule] || null,
  };
}

// ── API helpers (return null when the backend is unreachable) ─────────────────

async function nidsFetchAlerts(limit = 200, extra = {}) {
  try {
    const p = new URLSearchParams({ limit, ...extra });
    const r = await fetch(`/api/alerts?${p}`);
    if (!r.ok) return null;
    const data = await r.json();
    return Array.isArray(data) ? data.map(nidsEnrichAlert) : null;
  } catch { return null; }
}

async function nidsFetchHealth() {
  try {
    const r = await fetch("/api/health");
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

async function nidsFetchStats() {
  try {
    const r = await fetch("/api/stats");
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

async function nidsFetchAllowlist() {
  try {
    const r = await fetch("/api/allowlist");
    if (!r.ok) return null;
    const data = await r.json();
    return data.entries || [];
  } catch { return null; }
}

async function nidsAddAllowlistEntry(entry) {
  try {
    const r = await fetch("/api/allowlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ entry }),
    });
    return r.ok;
  } catch { return false; }
}

async function nidsRemoveAllowlistEntry(entry) {
  try {
    const r = await fetch("/api/allowlist", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ entry }),
    });
    return r.ok;
  } catch { return false; }
}

function nidsExportCSV(alerts) {
  const cols = ["id","timestamp","severity","rule","category","type","protocol",
                "src_ip","src_country","dst_ip","dst_port","count","ttl","length","mitre"];
  const rows = [cols.join(",")];
  alerts.forEach(a => rows.push(cols.map(c => {
    const v = a[c] == null ? "" : a[c];
    return typeof v === "string" && v.includes(",") ? `"${v}"` : v;
  }).join(",")));
  const blob = new Blob([rows.join("\n")], { type:"text/csv" });
  const url  = URL.createObjectURL(blob);
  const el   = document.createElement("a");
  el.href = url;
  el.download = `nids-alerts-${new Date().toISOString().slice(0,10)}.csv`;
  el.click();
  URL.revokeObjectURL(url);
}

Object.assign(window, {
  NIDS_RULES, NIDS_SEV, NIDS_CAT_COLOR, NIDS_CAT_LOOKUP, NIDS_MITRE_LOOKUP,
  NIDS_IP_GEO, NIDS_CONTINENTS, NIDS_IPS, NIDS_DST, NIDS_PORTS,
  nidsGenAlert, nidsGenHistory, nidsEnrichAlert,
  nidsFetchAlerts, nidsFetchHealth, nidsFetchStats,
  nidsFetchAllowlist, nidsAddAllowlistEntry, nidsRemoveAllowlistEntry,
  nidsExportCSV,
});
