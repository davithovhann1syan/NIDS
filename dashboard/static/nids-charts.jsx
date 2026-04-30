// nids-charts.jsx — Chart.js wrappers + SVG world map
'use strict';
const { useState, useEffect, useRef, useMemo } = React;

const CHART_OPTS = {
  tooltip:{ backgroundColor:"#16202e", titleColor:"#8fa3be", bodyColor:"#eef2f8", borderColor:"rgba(255,255,255,0.1)", borderWidth:1, padding:10 },
  grid:   { color:"rgba(255,255,255,0.03)" },
  tick:   { color:"#2d3f52", font:{ size:9, family:"JetBrains Mono" } },
};

// ─── TIMELINE CHART ───────────────────────────────────────────────────────────
function TimelineChart({ alerts }) {
  const ref=useRef(null), cRef=useRef(null);
  const buckets=useMemo(()=>{
    const b=Array(24).fill(null).map(()=>({c:0,h:0,m:0,l:0}));
    const now=Date.now();
    alerts.forEach(a=>{
      const i=23-Math.min(Math.floor((now-new Date(a.timestamp))/3600000),23);
      if(a.severity==="CRITICAL")b[i].c++; else if(a.severity==="HIGH")b[i].h++; else if(a.severity==="MEDIUM")b[i].m++; else b[i].l++;
    });
    return b;
  },[alerts]);
  const labels=useMemo(()=>buckets.map((_,i)=>new Date(Date.now()-(23-i)*3600000).getHours().toString().padStart(2,"0")+":00"),[buckets]);

  useEffect(()=>{
    if(!ref.current)return;
    cRef.current?.destroy();
    const mk=(color,key,fill)=>({ label:{c:"CRITICAL",h:"HIGH",m:"MEDIUM",l:"LOW"}[key], data:buckets.map(b=>b[key]), borderColor:color, backgroundColor:color+"18", fill, tension:0.4, pointRadius:0, pointHoverRadius:4, borderWidth:1.8 });
    cRef.current=new Chart(ref.current,{
      type:"line", data:{ labels, datasets:[mk("#ff3355","c",true),mk("#ff7c2a","h",false),mk("#ffbe2e","m",false),mk("#4a8fff","l",false)] },
      options:{ responsive:true, maintainAspectRatio:false, animation:false, interaction:{mode:"index",intersect:false},
        plugins:{ legend:{display:true,position:"top",labels:{color:"#4e6278",boxWidth:20,boxHeight:2,font:{size:10,family:"JetBrains Mono"},padding:10,usePointStyle:false}}, tooltip:CHART_OPTS.tooltip },
        scales:{ x:{grid:CHART_OPTS.grid,ticks:{...CHART_OPTS.tick,maxTicksLimit:8}}, y:{grid:CHART_OPTS.grid,ticks:CHART_OPTS.tick,beginAtZero:true} }
      }
    });
    return()=>cRef.current?.destroy();
  },[buckets,labels]);
  return <canvas ref={ref}/>;
}

// ─── DONUT CHART ──────────────────────────────────────────────────────────────
function DonutChart({ alerts }) {
  const ref=useRef(null), cRef=useRef(null);
  const counts=useMemo(()=>["CRITICAL","HIGH","MEDIUM","LOW"].map(s=>alerts.filter(a=>a.severity===s).length),[alerts]);
  useEffect(()=>{
    if(!ref.current)return;
    cRef.current?.destroy();
    cRef.current=new Chart(ref.current,{
      type:"doughnut",
      data:{labels:["CRITICAL","HIGH","MEDIUM","LOW"],datasets:[{data:counts,backgroundColor:["#ff3355","#ff7c2a","#ffbe2e","#4a8fff"],borderWidth:0,hoverOffset:5}]},
      options:{responsive:true,maintainAspectRatio:false,cutout:"76%",animation:false,plugins:{legend:{display:false},tooltip:CHART_OPTS.tooltip}}
    });
    return()=>cRef.current?.destroy();
  },[counts]);
  const total=counts.reduce((a,b)=>a+b,0);
  return (
    <div style={{position:"relative",height:130}}>
      <canvas ref={ref} style={{position:"absolute",inset:0}}/>
      <div style={{position:"absolute",inset:0,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",pointerEvents:"none"}}>
        <div style={{fontSize:20,fontWeight:700,fontFamily:"'JetBrains Mono',monospace",color:"#eef2f8",lineHeight:1}}>{total}</div>
        <div style={{fontSize:9,color:"#4e6278",textTransform:"uppercase",letterSpacing:"0.1em",marginTop:2}}>total</div>
      </div>
    </div>
  );
}

// ─── HORIZONTAL BAR CHART ─────────────────────────────────────────────────────
function HBarChart({ data, color, labelKey, valueKey, maxItems=8 }) {
  const ref=useRef(null), cRef=useRef(null);
  const slice=useMemo(()=>data.slice(0,maxItems),[data,maxItems]);
  useEffect(()=>{
    if(!ref.current||!slice.length)return;
    cRef.current?.destroy();
    cRef.current=new Chart(ref.current,{
      type:"bar",
      data:{labels:slice.map(d=>d[labelKey]),datasets:[{data:slice.map(d=>d[valueKey]),backgroundColor:color+"2a",borderColor:color+"bb",borderWidth:1.5,borderRadius:3}]},
      options:{indexAxis:"y",responsive:true,maintainAspectRatio:false,animation:false,
        plugins:{legend:{display:false},tooltip:CHART_OPTS.tooltip},
        scales:{x:{grid:CHART_OPTS.grid,ticks:CHART_OPTS.tick},y:{grid:{display:false},ticks:{...CHART_OPTS.tick,color:"#8fa3be"}}}
      }
    });
    return()=>cRef.current?.destroy();
  },[slice,color,labelKey,valueKey]);
  return <canvas ref={ref}/>;
}

// ─── PACKET RATE GAUGE ────────────────────────────────────────────────────────
function PacketRateGauge({ rate, max=600 }) {
  const pct=Math.min(rate/max,1);
  const toRad=d=>d*Math.PI/180;
  const cx=50,cy=52,r=36;
  const arcPath=(s,e)=>{
    const sv={x:cx+r*Math.cos(toRad(s)),y:cy+r*Math.sin(toRad(s))};
    const ev={x:cx+r*Math.cos(toRad(e)),y:cy+r*Math.sin(toRad(e))};
    return `M${sv.x.toFixed(1)},${sv.y.toFixed(1)} A${r},${r},0,${(e-s)>180?1:0},1,${ev.x.toFixed(1)},${ev.y.toFixed(1)}`;
  };
  const end=-140+pct*280;
  const nx=cx+r*0.72*Math.cos(toRad(end)),ny=cy+r*0.72*Math.sin(toRad(end));
  const gc=pct>0.8?"#ff3355":pct>0.5?"#ffbe2e":"#00dfa0";
  // Tick marks
  const ticks=[-140,-112,-84,-56,-28,0,28,56,84,112,140];
  return (
    <svg viewBox="0 0 100 72" style={{width:"100%",maxWidth:110,display:"block",margin:"0 auto"}}>
      {ticks.map(a=>{
        const innerR=r-4,outerR=r-1;
        const ix=cx+innerR*Math.cos(toRad(a)),iy=cy+innerR*Math.sin(toRad(a));
        const ox=cx+outerR*Math.cos(toRad(a)),oy=cy+outerR*Math.sin(toRad(a));
        return <line key={a} x1={ix.toFixed(1)} y1={iy.toFixed(1)} x2={ox.toFixed(1)} y2={oy.toFixed(1)} stroke="rgba(255,255,255,0.12)" strokeWidth="0.8"/>;
      })}
      <path d={arcPath(-140,140)} fill="none" stroke="#1c2a3c" strokeWidth="5.5" strokeLinecap="round"/>
      <path d={arcPath(-140,Math.max(-139.9,end))} fill="none" stroke={gc} strokeWidth="5.5" strokeLinecap="round"/>
      <line x1={cx} y1={cy} x2={nx.toFixed(1)} y2={ny.toFixed(1)} stroke="#eef2f8" strokeWidth="1.5" strokeLinecap="round"/>
      <circle cx={cx} cy={cy} r={3} fill="#eef2f8"/>
      <circle cx={cx} cy={cy} r={1.2} fill="#060c18"/>
      <text x={cx} y={cy+18} textAnchor="middle" fontSize="9.5" fontFamily="JetBrains Mono" fill={gc} fontWeight="bold">{rate}</text>
      <text x={cx} y={cy+27} textAnchor="middle" fontSize="6.5" fill="#4e6278" fontFamily="JetBrains Mono">pkt/s</text>
    </svg>
  );
}

// ─── WORLD MAP ────────────────────────────────────────────────────────────────
function WorldMap({ alerts, onIpClick }) {
  const W=1000,H=480;
  const proj=(lon,lat)=>[(lon+180)/360*W,(90-lat)/180*H];
  const [hovered,setHovered]=useState(null);

  const attackData=useMemo(()=>{
    const m={};
    alerts.forEach(a=>{
      const geo=NIDS_IP_GEO[a.src_ip];
      if(!geo)return;
      if(!m[a.src_ip])m[a.src_ip]={...geo,ip:a.src_ip,count:0,sev:"LOW",critCount:0};
      m[a.src_ip].count++;
      if(a.severity==="CRITICAL")m[a.src_ip].critCount++;
      const ord=["LOW","MEDIUM","HIGH","CRITICAL"];
      if(ord.indexOf(a.severity)>ord.indexOf(m[a.src_ip].sev))m[a.src_ip].sev=a.severity;
    });
    return Object.values(m).sort((a,b)=>b.count-a.count);
  },[alerts]);

  const totalAttackers=attackData.length;
  const totalCountries=new Set(attackData.map(d=>d.country)).size;

  return (
    <div style={{position:"relative",width:"100%",background:"#06080f",borderRadius:8,overflow:"hidden"}}>
      <svg viewBox={`0 0 ${W} ${H}`} style={{width:"100%",display:"block"}} preserveAspectRatio="xMidYMid meet">
        {/* Ocean */}
        <rect width={W} height={H} fill="#06080f"/>
        {/* Lat/lon grid */}
        {[-60,-30,0,30,60].map(lat=>{
          const y=(90-lat)/180*H;
          return <line key={lat} x1={0} y1={y} x2={W} y2={y} stroke="rgba(255,255,255,0.035)" strokeWidth="0.5"/>;
        })}
        {[-120,-60,0,60,120].map(lon=>{
          const x=(lon+180)/360*W;
          return <line key={lon} x1={x} y1={0} x2={x} y2={H} stroke="rgba(255,255,255,0.035)" strokeWidth="0.5"/>;
        })}
        {/* Equator */}
        <line x1={0} y1={H/2} x2={W} y2={H/2} stroke="rgba(0,212,255,0.07)" strokeWidth="1"/>
        {/* Prime meridian */}
        <line x1={W/2} y1={0} x2={W/2} y2={H} stroke="rgba(0,212,255,0.07)" strokeWidth="1"/>

        {/* Continents */}
        {NIDS_CONTINENTS.map(c=>{
          const pts=c.d.map(([lon,lat])=>proj(lon,lat).join(",")).join(" ");
          return (
            <polygon key={c.id} points={pts} fill="#111e30" stroke="rgba(0,212,255,0.2)" strokeWidth="0.8"/>
          );
        })}

        {/* Attack dots */}
        {attackData.map((dot)=>{
          const [cx,cy]=proj(dot.lon,dot.lat);
          const s=NIDS_SEV[dot.sev];
          const r=Math.min(3+Math.log(dot.count+1)*2.8,15);
          const isHot=dot.critCount>0;
          const isHov=hovered?.ip===dot.ip;
          return (
            <g key={dot.ip} style={{cursor:"pointer"}}
              onMouseEnter={()=>setHovered(dot)}
              onMouseLeave={()=>setHovered(null)}
              onClick={()=>onIpClick&&onIpClick(dot.ip)}>
              <circle cx={cx} cy={cy} r={r*3.5} fill={s.color} opacity="0.05"/>
              {isHot&&<circle cx={cx} cy={cy} r={r*2} fill="none" stroke={s.color} strokeWidth="0.7" opacity="0.35" style={{animation:"nids-ring-pulse 2.2s ease-in-out infinite"}}/>}
              <circle cx={cx} cy={cy} r={r} fill={s.color} opacity={isHov?1:0.72}/>
              <circle cx={cx} cy={cy} r={r*0.42} fill="#fff" opacity="0.65"/>
            </g>
          );
        })}

        {/* Hover tooltip */}
        {hovered&&(()=>{
          const [cx,cy]=proj(hovered.lon,hovered.lat);
          const tx=cx>700?cx-138:cx+10, ty=cy>360?cy-72:cy+10;
          const s=NIDS_SEV[hovered.sev];
          return (
            <g style={{pointerEvents:"none"}}>
              <rect x={tx} y={ty} width={136} height={68} rx={5} fill="#16202e" stroke={s.color+"60"} strokeWidth="0.8"/>
              <text x={tx+10} y={ty+15} fontSize={9.5} fill="#8fa3be" fontFamily="JetBrains Mono">{hovered.ip}</text>
              <text x={tx+10} y={ty+28} fontSize={8.5} fill={s.color} fontFamily="JetBrains Mono" fontWeight="bold">{hovered.country}</text>
              <text x={tx+10} y={ty+43} fontSize={9} fill="#eef2f8" fontFamily="JetBrains Mono">{hovered.count} alerts · {hovered.critCount} crit</text>
              <text x={tx+10} y={ty+58} fontSize={8} fill="#4e6278" fontFamily="JetBrains Mono">Click to filter</text>
            </g>
          );
        })()}
      </svg>

      {/* Map stats overlay */}
      <div style={{position:"absolute",bottom:8,left:10,display:"flex",gap:14}}>
        <div style={{fontSize:10,fontFamily:"'JetBrains Mono',monospace",color:"#4e6278"}}>
          <span style={{color:"#00d4ff",fontWeight:700}}>{totalAttackers}</span> source IPs
        </div>
        <div style={{fontSize:10,fontFamily:"'JetBrains Mono',monospace",color:"#4e6278"}}>
          <span style={{color:"#00d4ff",fontWeight:700}}>{totalCountries}</span> countries
        </div>
      </div>

      {/* Legend */}
      <div style={{position:"absolute",top:8,right:10,display:"flex",gap:10}}>
        {["CRITICAL","HIGH","MEDIUM"].map(s=>(
          <div key={s} style={{display:"flex",alignItems:"center",gap:5,fontSize:9,fontFamily:"'JetBrains Mono',monospace",color:"#4e6278"}}>
            <span style={{width:7,height:7,borderRadius:"50%",background:NIDS_SEV[s].color,display:"inline-block"}}/>
            {s}
          </div>
        ))}
      </div>
    </div>
  );
}

Object.assign(window, { TimelineChart, DonutChart, HBarChart, PacketRateGauge, WorldMap });
