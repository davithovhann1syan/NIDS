'use strict';
// NIDS Data Engine — plain JS, no JSX, loaded first

const NIDS_RULES = [
  { name:"Port Scan (SYN)",         cat:"Recon",       sev:"HIGH",     type:"rate"    },
  { name:"XMAS Scan",               cat:"Recon",       sev:"MEDIUM",   type:"pattern" },
  { name:"NULL Scan",               cat:"Recon",       sev:"MEDIUM",   type:"pattern" },
  { name:"FIN Scan",                cat:"Recon",       sev:"MEDIUM",   type:"pattern" },
  { name:"ACK Scan",                cat:"Recon",       sev:"LOW",      type:"pattern" },
  { name:"Ping Sweep",              cat:"Recon",       sev:"LOW",      type:"rate"    },
  { name:"UDP Port Scan",           cat:"Recon",       sev:"LOW",      type:"rate"    },
  { name:"OS Fingerprinting",       cat:"Recon",       sev:"MEDIUM",   type:"pattern" },
  { name:"Slow Scan",               cat:"Recon",       sev:"LOW",      type:"rate"    },
  { name:"SSH Brute Force",         cat:"Brute Force", sev:"HIGH",     type:"rate"    },
  { name:"FTP Brute Force",         cat:"Brute Force", sev:"HIGH",     type:"rate"    },
  { name:"RDP Brute Force",         cat:"Brute Force", sev:"HIGH",     type:"rate"    },
  { name:"SMB Brute Force",         cat:"Brute Force", sev:"HIGH",     type:"rate"    },
  { name:"VNC Brute Force",         cat:"Brute Force", sev:"HIGH",     type:"rate"    },
  { name:"MySQL Brute Force",       cat:"Brute Force", sev:"MEDIUM",   type:"rate"    },
  { name:"Redis Brute Force",       cat:"Brute Force", sev:"MEDIUM",   type:"rate"    },
  { name:"Telnet Brute Force",      cat:"Brute Force", sev:"MEDIUM",   type:"rate"    },
  { name:"LDAP Brute Force",        cat:"Brute Force", sev:"MEDIUM",   type:"rate"    },
  { name:"EternalBlue (MS17-010)",  cat:"Exploit",     sev:"CRITICAL", type:"pattern" },
  { name:"BlueKeep",                cat:"Exploit",     sev:"CRITICAL", type:"pattern" },
  { name:"Log4Shell",               cat:"Exploit",     sev:"CRITICAL", type:"pattern" },
  { name:"Shellshock",              cat:"Exploit",     sev:"CRITICAL", type:"pattern" },
  { name:"PrintNightmare",          cat:"Exploit",     sev:"CRITICAL", type:"pattern" },
  { name:"SQL Injection (HTTP)",    cat:"Exploit",     sev:"HIGH",     type:"pattern" },
  { name:"PHP Webshell",            cat:"Exploit",     sev:"CRITICAL", type:"pattern" },
  { name:"Log4Shell (POST)",        cat:"Exploit",     sev:"CRITICAL", type:"pattern" },
  { name:"Cobalt Strike Beacon",    cat:"Malware/C2",  sev:"CRITICAL", type:"pattern" },
  { name:"Metasploit Default",      cat:"Malware/C2",  sev:"HIGH",     type:"pattern" },
  { name:"DNS Tunneling",           cat:"Malware/C2",  sev:"HIGH",     type:"rate"    },
  { name:"ICMP Tunneling",          cat:"Malware/C2",  sev:"HIGH",     type:"pattern" },
  { name:"Reverse Shell Port",      cat:"Malware/C2",  sev:"CRITICAL", type:"pattern" },
  { name:"Empire C2",               cat:"Malware/C2",  sev:"CRITICAL", type:"pattern" },
  { name:"IRC Botnet",              cat:"Malware/C2",  sev:"HIGH",     type:"rate"    },
  { name:"Large Outbound Transfer", cat:"Exfil",       sev:"HIGH",     type:"rate"    },
  { name:"DNS Exfiltration",        cat:"Exfil",       sev:"HIGH",     type:"rate"    },
  { name:"Abnormal TTL",            cat:"Exfil",       sev:"MEDIUM",   type:"pattern" },
  { name:"High-Freq Small Packets", cat:"Exfil",       sev:"MEDIUM",   type:"rate"    },
  { name:"Tor Exit Node",           cat:"Policy",      sev:"MEDIUM",   type:"pattern" },
  { name:"Crypto Mining",           cat:"Policy",      sev:"MEDIUM",   type:"pattern" },
  { name:"BitTorrent P2P",          cat:"Policy",      sev:"LOW",      type:"pattern" },
  { name:"Cleartext Telnet",        cat:"Policy",      sev:"LOW",      type:"pattern" },
  { name:"Cleartext FTP",           cat:"Policy",      sev:"LOW",      type:"pattern" },
  { name:"Open Proxy",              cat:"Policy",      sev:"MEDIUM",   type:"pattern" },
  { name:"Lateral Movement",        cat:"Internal",    sev:"HIGH",     type:"rate"    },
  { name:"ARP Spoofing",            cat:"Internal",    sev:"HIGH",     type:"pattern" },
  { name:"Internal Host Sweep",     cat:"Internal",    sev:"MEDIUM",   type:"rate"    },
  { name:"SMB Spread",              cat:"Internal",    sev:"HIGH",     type:"rate"    },
  { name:"RPC Abuse",               cat:"Internal",    sev:"MEDIUM",   type:"pattern" },
];

const NIDS_SEV = {
  CRITICAL: { color:"#ff3355", bg:"rgba(255,51,85,0.1)",  glow:"rgba(255,51,85,0.35)",  short:"CRIT" },
  HIGH:     { color:"#ff7c2a", bg:"rgba(255,124,42,0.1)", glow:"rgba(255,124,42,0.3)",  short:"HIGH" },
  MEDIUM:   { color:"#ffbe2e", bg:"rgba(255,190,46,0.1)", glow:"rgba(255,190,46,0.2)",  short:"MED"  },
  LOW:      { color:"#4a8fff", bg:"rgba(74,143,255,0.1)", glow:"rgba(74,143,255,0.2)",  short:"LOW"  },
};

const NIDS_CAT_COLOR = {
  "Recon":       "#4a8fff",
  "Brute Force": "#ff7c2a",
  "Exploit":     "#ff3355",
  "Malware/C2":  "#9b6fff",
  "Exfil":       "#ff6090",
  "Policy":      "#00dfa0",
  "Internal":    "#ffbe2e",
};

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

const NIDS_IPS  = Object.keys(NIDS_IP_GEO);
const NIDS_DST  = ["10.0.0.1","10.0.0.2","10.0.0.10","192.168.1.1","192.168.1.5","172.16.0.1","10.0.1.20"];
const NIDS_PORTS = [22,23,21,80,443,445,3389,4444,1337,8080,53,3306,5432,6379,27017,6666,9001,2222];
const NIDS_PROTO = { 6:"TCP", 17:"UDP", 1:"ICMP" };

let _uid = 1000;
function nidsGenAlert(ts) {
  const r   = NIDS_RULES[Math.floor(Math.random()*NIDS_RULES.length)];
  const src = NIDS_IPS[Math.floor(Math.random()*NIDS_IPS.length)];
  const proto = [6,6,6,17,1][Math.floor(Math.random()*5)];
  return {
    id:        ++_uid,
    timestamp: ts || new Date(),
    rule:      r.name,
    category:  r.cat,
    severity:  r.sev,
    type:      r.type,
    protocol:  NIDS_PROTO[proto] || "TCP",
    src_ip:    src,
    src_country: NIDS_IP_GEO[src]?.country || "Unknown",
    dst_ip:    NIDS_DST[Math.floor(Math.random()*NIDS_DST.length)],
    dst_port:  NIDS_PORTS[Math.floor(Math.random()*NIDS_PORTS.length)],
    count:     r.type==="rate" ? Math.floor(Math.random()*300)+10 : null,
    ttl:       Math.floor(Math.random()*200)+20,
    length:    Math.floor(Math.random()*1400)+40,
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

function nidsExportCSV(alerts) {
  const cols = ["id","timestamp","severity","rule","category","type","protocol","src_ip","src_country","dst_ip","dst_port","count","ttl","length"];
  const rows = [cols.join(",")];
  alerts.forEach(a => rows.push(cols.map(c=>{
    const v = a[c]===null||a[c]===undefined?"":a[c];
    return typeof v==="string"&&v.includes(",") ? `"${v}"` : v;
  }).join(",")));
  const blob = new Blob([rows.join("\n")],{type:"text/csv"});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href=url; a.download=`nids-alerts-${new Date().toISOString().slice(0,10)}.csv`;
  a.click(); URL.revokeObjectURL(url);
}

Object.assign(window, {
  NIDS_RULES, NIDS_SEV, NIDS_CAT_COLOR, NIDS_IP_GEO, NIDS_CONTINENTS,
  NIDS_IPS, NIDS_DST, NIDS_PORTS, nidsGenAlert, nidsGenHistory, nidsExportCSV,
});
