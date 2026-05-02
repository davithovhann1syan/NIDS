// nids-ui.jsx — Shared UI primitives + InvestigateDrawer
'use strict';
const { useState, useEffect, useRef, useMemo, useCallback } = React;

// ─── SEVERITY BADGE ───────────────────────────────────────────────────────────
function SevBadge({ sev, small }) {
  const s = NIDS_SEV[sev] || NIDS_SEV.LOW;
  return (
    <span style={{
      display:"inline-flex", alignItems:"center", justifyContent:"center",
      padding:small?"1px 5px":"2px 8px", borderRadius:3,
      fontSize:small?9:10, fontWeight:700, fontFamily:"'JetBrains Mono',monospace",
      letterSpacing:"0.08em", color:s.color, background:s.bg,
      border:`1px solid ${s.color}55`, flexShrink:0, whiteSpace:"nowrap",
    }}>{s.short}</span>
  );
}

// ─── CATEGORY CHIP ────────────────────────────────────────────────────────────
function CatChip({ cat, small }) {
  const c = NIDS_CAT_COLOR[cat] || "#566880";
  return (
    <span style={{display:"inline-flex",alignItems:"center",gap:4,fontSize:small?9:10,color:c,fontFamily:"'JetBrains Mono',monospace"}}>
      <span style={{width:5,height:5,borderRadius:1,background:c,flexShrink:0,display:"inline-block"}}/>
      {cat}
    </span>
  );
}

// ─── MITRE BADGE ──────────────────────────────────────────────────────────────
function MitreBadge({ id }) {
  if (!id) return null;
  return (
    <span style={{
      display:"inline-flex", alignItems:"center",
      fontSize:9, fontFamily:"'JetBrains Mono',monospace",
      color:"#9b6fff", background:"rgba(155,111,255,0.1)",
      border:"1px solid rgba(155,111,255,0.28)", borderRadius:3,
      padding:"1px 6px", flexShrink:0, whiteSpace:"nowrap",
      cursor:"default",
    }} title={`MITRE ATT&CK ${id}`}>{id}</span>
  );
}

// ─── LIVE DOT ─────────────────────────────────────────────────────────────────
function LiveDot({ color, size=7, animate=true }) {
  return (
    <span style={{position:"relative",display:"inline-flex",alignItems:"center",justifyContent:"center",width:size,height:size,flexShrink:0}}>
      {animate&&<span style={{position:"absolute",inset:0,borderRadius:"50%",background:color,opacity:0.2,animation:"nids-pulse 2s infinite"}}/>}
      <span style={{width:size*.65,height:size*.65,borderRadius:"50%",background:color,boxShadow:`0 0 ${size}px ${color}`}}/>
    </span>
  );
}

// ─── MINI SPARKLINE ───────────────────────────────────────────────────────────
function MiniSpark({ data, color, height=26 }) {
  if (!data||data.length<2) return null;
  const max=Math.max(...data,1), W=80, H=height;
  const pts=data.map((v,i)=>`${(i/(data.length-1))*(W-2)+1},${H-1-(v/max)*(H-4)}`).join(" ");
  const gid=`sg${color.replace(/[^a-z0-9]/gi,"")}`;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{width:"100%",height}} preserveAspectRatio="none">
      <defs><linearGradient id={gid} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={color} stopOpacity="0.35"/><stop offset="100%" stopColor={color} stopOpacity="0"/></linearGradient></defs>
      <polygon points={`1,${H-1} ${pts} ${W-1},${H-1}`} fill={`url(#${gid})`}/>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.6" strokeLinejoin="round" strokeLinecap="round"/>
    </svg>
  );
}

// ─── STAT CARD ────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, color, glow, trend, spark, icon }) {
  const isCrit = glow && color==="#ff3355";
  return (
    <div style={{
      background:"#111828", border:`1px solid ${glow?color+"55":"rgba(255,255,255,0.06)"}`,
      borderRadius:10, padding:"14px 16px", display:"flex", flexDirection:"column", gap:5,
      flex:1, minWidth:0, position:"relative", overflow:"hidden",
      boxShadow:isCrit?"0 0 32px rgba(255,51,85,0.18)":glow?`0 0 20px ${color}14`:"none",
      animation:isCrit?"nids-glow-pulse 3s ease-in-out infinite":"none",
    }}>
      {glow&&<div style={{position:"absolute",top:0,left:0,right:0,height:2,background:`linear-gradient(90deg,${color},transparent)`,opacity:0.9}}/>}
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
        <span style={{fontSize:10,fontWeight:600,color:"#4e6278",textTransform:"uppercase",letterSpacing:"0.1em"}}>{label}</span>
        {icon&&<span style={{color:color||"#4e6278",opacity:0.6}}>{icon}</span>}
      </div>
      <div style={{display:"flex",alignItems:"flex-end",gap:8}}>
        <span style={{fontSize:26,fontWeight:700,fontFamily:"'JetBrains Mono',monospace",color:color||"#eef2f8",lineHeight:1,letterSpacing:"-0.02em"}}>{value}</span>
        {trend!=null&&<span style={{fontSize:11,color:trend>0?"#ff7c2a":"#00dfa0",marginBottom:3,fontFamily:"'JetBrains Mono',monospace"}}>{trend>0?"▲":"▼"}{Math.abs(trend)}%</span>}
      </div>
      {spark&&<MiniSpark data={spark} color={color||"#00d4ff"} height={22}/>}
      {sub&&<div style={{fontSize:10,color:"#4e6278",marginTop:-2}}>{sub}</div>}
    </div>
  );
}

// ─── CHART CARD ───────────────────────────────────────────────────────────────
function ChartCard({ title, subtitle, children, style, action }) {
  return (
    <div style={{background:"#111828",border:"1px solid rgba(255,255,255,0.06)",borderRadius:10,padding:"14px 16px",display:"flex",flexDirection:"column",...style}}>
      <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:10}}>
        <div>
          <div style={{fontSize:11,fontWeight:600,color:"#8fa3be",textTransform:"uppercase",letterSpacing:"0.08em"}}>{title}</div>
          {subtitle&&<div style={{fontSize:10,color:"#4e6278",marginTop:1}}>{subtitle}</div>}
        </div>
        {action}
      </div>
      {children}
    </div>
  );
}

// ─── TOAST SYSTEM ─────────────────────────────────────────────────────────────
function ToastContainer({ toasts, dismiss }) {
  return (
    <div style={{position:"fixed",top:14,right:14,zIndex:9999,display:"flex",flexDirection:"column",gap:7,maxWidth:320,pointerEvents:"none"}}>
      {toasts.map(t=>{
        const s=NIDS_SEV[t.severity]||NIDS_SEV.HIGH;
        return (
          <div key={t.id} onClick={()=>dismiss(t.id)} style={{
            background:"#16202e",border:`1px solid ${s.color}55`,borderLeft:`3px solid ${s.color}`,
            borderRadius:8,padding:"10px 13px",
            boxShadow:`0 4px 24px rgba(0,0,0,0.6),0 0 20px ${s.color}18`,
            pointerEvents:"all",cursor:"pointer",animation:"nids-toast-in 0.2s ease",
          }}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
              <SevBadge sev={t.severity} small/>
              <span style={{fontSize:11,fontWeight:600,color:"#eef2f8",flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{t.rule}</span>
              <span style={{fontSize:11,color:"#4e6278",flexShrink:0}}>✕</span>
            </div>
            <div style={{fontSize:10,fontFamily:"'JetBrains Mono',monospace",color:s.color}}>{t.src_ip} <span style={{color:"#4e6278"}}>→</span> {t.dst_ip}:{t.dst_port}</div>
            <div style={{fontSize:9,color:"#4e6278",marginTop:3}}>{new Date(t.timestamp).toLocaleTimeString("en-US",{hour12:false})} · {t.src_country}</div>
          </div>
        );
      })}
    </div>
  );
}

// ─── SHORTCUTS OVERLAY ────────────────────────────────────────────────────────
function ShortcutsOverlay({ onClose }) {
  useEffect(()=>{
    const h=e=>{if(e.key==="Escape")onClose();};
    window.addEventListener("keydown",h);
    return()=>window.removeEventListener("keydown",h);
  },[onClose]);
  return (
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.72)",zIndex:9998,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={onClose}>
      <div style={{background:"#111828",border:"1px solid rgba(255,255,255,0.12)",borderRadius:12,padding:"24px 28px",maxWidth:380,width:"90%"}} onClick={e=>e.stopPropagation()}>
        <div style={{fontSize:14,fontWeight:700,color:"#eef2f8",marginBottom:16}}>Keyboard Shortcuts</div>
        {[
          ["P","Pause / resume live feed"],
          ["E","Export filtered alerts as CSV"],
          ["C","Clear all filters"],
          ["T","Toggle light / dark mode"],
          ["/","Focus rule search"],
          ["1–7","Switch views (Dashboard · Alerts · Map · Rules · Analytics · Allowlist · PCAP)"],
          ["?","Show / hide this panel"],
          ["Esc","Close overlays / dismiss"],
        ].map(([k,d])=>(
          <div key={k} style={{display:"flex",alignItems:"center",gap:12,padding:"6px 0",borderBottom:"1px solid rgba(255,255,255,0.04)"}}>
            <kbd style={{background:"#1c2a3c",border:"1px solid rgba(255,255,255,0.14)",borderRadius:4,padding:"2px 9px",fontFamily:"'JetBrains Mono',monospace",fontSize:11,color:"#00d4ff",minWidth:30,textAlign:"center",flexShrink:0}}>{k}</kbd>
            <span style={{fontSize:12,color:"#8fa3be"}}>{d}</span>
          </div>
        ))}
        <button onClick={onClose} style={{marginTop:14,padding:"8px",borderRadius:6,background:"rgba(255,255,255,0.05)",color:"#8fa3be",fontSize:12,width:"100%",border:"1px solid rgba(255,255,255,0.08)"}}>Close  <kbd style={{background:"#111",border:"1px solid rgba(255,255,255,0.14)",borderRadius:3,padding:"1px 6px",fontSize:10,marginLeft:6}}>Esc</kbd></button>
      </div>
    </div>
  );
}

// ─── BLOCKED IP BADGE ─────────────────────────────────────────────────────────
function BlockedBadge() {
  return (
    <span style={{display:"inline-flex",alignItems:"center",gap:3,fontSize:9,fontFamily:"'JetBrains Mono',monospace",color:"#ff3355",background:"rgba(255,51,85,0.12)",border:"1px solid rgba(255,51,85,0.35)",borderRadius:3,padding:"1px 5px"}}>
      ⊘ BLOCKED
    </span>
  );
}

// ─── INVESTIGATE DRAWER ───────────────────────────────────────────────────────
function InvestigateDrawer({ ip, alerts, blockedIPs, onBlock, onClose }) {
  if (!ip) return null;

  const ipAlerts = useMemo(()=>alerts.filter(a=>a.src_ip===ip), [alerts, ip]);
  const blocked  = blockedIPs.has(ip);
  const geo      = NIDS_IP_GEO[ip] || {};
  const country  = geo.country || ipAlerts[0]?.src_country || "Unknown";

  const critCount = ipAlerts.filter(a=>a.severity==="CRITICAL").length;
  const highCount = ipAlerts.filter(a=>a.severity==="HIGH").length;
  const riskScore = Math.min(100, critCount*20 + highCount*8 + Math.min(ipAlerts.length*2, 40));
  const riskColor = riskScore>=80?"#ff3355":riskScore>=50?"#ff7c2a":riskScore>=20?"#ffbe2e":"#00dfa0";
  const riskLabel = riskScore>=80?"CRITICAL":riskScore>=50?"HIGH":riskScore>=20?"ELEVATED":"LOW";

  const ruleMap = useMemo(()=>{
    const m={};
    ipAlerts.forEach(a=>{ m[a.rule]=(m[a.rule]||0)+1; });
    return Object.entries(m).sort((a,b)=>b[1]-a[1]).slice(0,6);
  },[ipAlerts]);
  const maxRule = ruleMap[0]?.[1]||1;

  const timestamps = ipAlerts.map(a=>new Date(a.timestamp).getTime()).filter(Boolean);
  const firstSeen  = timestamps.length ? new Date(Math.min(...timestamps)).toLocaleString() : "—";
  const lastSeen   = timestamps.length ? new Date(Math.max(...timestamps)).toLocaleString() : "—";

  const mitreSet = new Set(ipAlerts.map(a=>a.mitre).filter(Boolean));

  // Close on Escape
  useEffect(()=>{
    const h=e=>{ if(e.key==="Escape") onClose(); };
    window.addEventListener("keydown",h);
    return()=>window.removeEventListener("keydown",h);
  },[onClose]);

  return (
    <>
      {/* Backdrop */}
      <div onClick={onClose} style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.35)",zIndex:999}}/>
      {/* Panel */}
      <div style={{position:"fixed",right:0,top:0,bottom:0,width:360,background:"var(--bg1)",borderLeft:"1px solid var(--border-hi)",zIndex:1000,display:"flex",flexDirection:"column",boxShadow:"-12px 0 48px rgba(0,0,0,0.7)"}}>

        {/* Header */}
        <div style={{padding:"14px 16px",borderBottom:"1px solid var(--border)",flexShrink:0}}>
          <div style={{display:"flex",alignItems:"center",gap:8}}>
            <span style={{width:9,height:9,borderRadius:"50%",background:riskColor,boxShadow:`0 0 8px ${riskColor}`,flexShrink:0}}/>
            <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:14,fontWeight:700,color:"var(--cyan)",flex:1,overflow:"hidden",textOverflow:"ellipsis"}}>{ip}</span>
            <button onClick={onClose} style={{color:"var(--text3)",fontSize:14,padding:"2px 6px",borderRadius:4,background:"var(--bg4)",border:"1px solid var(--border-md)"}}>✕</button>
          </div>
          <div style={{fontSize:11,color:"var(--text2)",marginTop:5,display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
            <span>{country}</span>
            <span style={{color:"var(--text3)"}}>·</span>
            <span>{ipAlerts.length} alerts</span>
            {blocked && <BlockedBadge/>}
          </div>
        </div>

        {/* Risk score */}
        <div style={{padding:"12px 16px",borderBottom:"1px solid var(--border)",flexShrink:0}}>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:7}}>
            <span style={{fontSize:9,fontWeight:600,color:"var(--text3)",letterSpacing:"0.12em"}}>RISK SCORE</span>
            <span style={{fontSize:10,fontWeight:700,fontFamily:"'JetBrains Mono',monospace",color:riskColor}}>{riskLabel}</span>
          </div>
          <div style={{height:7,background:"var(--bg5)",borderRadius:4}}>
            <div style={{height:7,background:`linear-gradient(90deg,${riskColor}88,${riskColor})`,borderRadius:4,width:`${riskScore}%`,transition:"width .4s"}}/>
          </div>
          <div style={{display:"flex",justifyContent:"space-between",marginTop:4}}>
            <span style={{fontSize:9,color:"var(--text3)"}}>0</span>
            <span style={{fontSize:11,fontWeight:700,fontFamily:"'JetBrains Mono',monospace",color:riskColor}}>{riskScore}/100</span>
            <span style={{fontSize:9,color:"var(--text3)"}}>100</span>
          </div>
        </div>

        {/* Quick stats grid */}
        <div style={{padding:"10px 16px",borderBottom:"1px solid var(--border)",display:"grid",gridTemplateColumns:"repeat(4,1fr)",flexShrink:0}}>
          {[
            ["CRIT",  critCount,         "#ff3355"],
            ["HIGH",  highCount,         "#ff7c2a"],
            ["TOTAL", ipAlerts.length,   "var(--text1)"],
            ["RULES", ruleMap.length,    "var(--cyan)"],
          ].map(([lbl,val,col])=>(
            <div key={lbl} style={{textAlign:"center",padding:"6px 0"}}>
              <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:18,fontWeight:700,color:val>0?col:"var(--text3)",lineHeight:1}}>{val}</div>
              <div style={{fontSize:8,color:"var(--text3)",marginTop:3,letterSpacing:"0.1em"}}>{lbl}</div>
            </div>
          ))}
        </div>

        {/* Scrollable body */}
        <div style={{flex:1,overflowY:"auto",padding:"12px 16px"}}>

          {/* Activity window */}
          <div style={{marginBottom:14}}>
            <div style={{fontSize:9,fontWeight:600,color:"var(--text3)",letterSpacing:"0.12em",marginBottom:8}}>ACTIVITY WINDOW</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
              {[["First seen",firstSeen],["Last seen",lastSeen]].map(([l,v])=>(
                <div key={l} style={{background:"var(--bg3)",borderRadius:6,padding:"8px 10px"}}>
                  <div style={{fontSize:9,color:"var(--text3)",marginBottom:3}}>{l}</div>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"var(--text1)",wordBreak:"break-all"}}>{v}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Top rules */}
          {ruleMap.length>0&&(
            <div style={{marginBottom:14}}>
              <div style={{fontSize:9,fontWeight:600,color:"var(--text3)",letterSpacing:"0.12em",marginBottom:8}}>TOP TRIGGERED RULES</div>
              {ruleMap.map(([rule,count])=>(
                <div key={rule} style={{marginBottom:8}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:3}}>
                    <span style={{fontSize:11,color:"var(--text1)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:"82%"}}>{rule}</span>
                    <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:"var(--text2)",flexShrink:0}}>{count}×</span>
                  </div>
                  <div style={{height:3,background:"var(--bg5)",borderRadius:2}}>
                    <div style={{height:3,background:"var(--orange)",borderRadius:2,width:`${(count/maxRule)*100}%`,opacity:0.75}}/>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* MITRE techniques */}
          {mitreSet.size>0&&(
            <div style={{marginBottom:14}}>
              <div style={{fontSize:9,fontWeight:600,color:"var(--text3)",letterSpacing:"0.12em",marginBottom:8}}>MITRE ATT&amp;CK TECHNIQUES</div>
              <div style={{display:"flex",flexWrap:"wrap",gap:5}}>
                {[...mitreSet].map(t=><MitreBadge key={t} id={t}/>)}
              </div>
            </div>
          )}

          {/* Recent events */}
          <div>
            <div style={{fontSize:9,fontWeight:600,color:"var(--text3)",letterSpacing:"0.12em",marginBottom:8}}>RECENT EVENTS</div>
            {ipAlerts.slice(0,10).map(a=>(
              <div key={a.id} style={{padding:"7px 0",borderBottom:"1px solid var(--border)",display:"flex",gap:8,alignItems:"flex-start"}}>
                <SevBadge sev={a.severity} small/>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:11,color:"var(--text0)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{a.rule}</div>
                  <div style={{display:"flex",gap:8,marginTop:2,flexWrap:"wrap"}}>
                    <span style={{fontSize:9,color:"var(--text3)",fontFamily:"'JetBrains Mono',monospace"}}>{new Date(a.timestamp).toLocaleTimeString("en-US",{hour12:false})}</span>
                    {a.dst_port&&<span style={{fontSize:9,color:"var(--text3)",fontFamily:"'JetBrains Mono',monospace"}}>→ :{a.dst_port}</span>}
                    {a.mitre&&<MitreBadge id={a.mitre}/>}
                  </div>
                </div>
              </div>
            ))}
            {ipAlerts.length===0&&(
              <div style={{fontSize:11,color:"var(--text3)",textAlign:"center",padding:"24px 0"}}>No alerts for this IP in current window</div>
            )}
          </div>
        </div>

        {/* Action bar */}
        <div style={{padding:"12px 16px",borderTop:"1px solid var(--border)",display:"flex",gap:8,flexShrink:0}}>
          <button onClick={()=>onBlock(ip)} style={{flex:1,padding:"8px",borderRadius:6,fontSize:11,fontWeight:600,background:blocked?"rgba(0,223,160,0.1)":"rgba(255,51,85,0.1)",border:`1px solid ${blocked?"rgba(0,223,160,0.3)":"rgba(255,51,85,0.3)"}`,color:blocked?"var(--green)":"var(--red)"}}>
            {blocked?"✓ Unblock":"⊘ Block IP"}
          </button>
          <button onClick={()=>navigator.clipboard?.writeText(ip).catch(()=>{})} style={{padding:"8px 12px",borderRadius:6,fontSize:11,background:"var(--bg4)",border:"1px solid var(--border-md)",color:"var(--text1)"}}>
            Copy IP
          </button>
        </div>
      </div>
    </>
  );
}

Object.assign(window, {
  SevBadge, CatChip, MitreBadge, LiveDot, MiniSpark, StatCard, ChartCard,
  ToastContainer, ShortcutsOverlay, BlockedBadge, InvestigateDrawer,
});
