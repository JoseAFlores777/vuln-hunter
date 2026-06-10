// FUENTE del panel (JSX). Compila con scripts/build-panel.sh -> panel/index.html
const {useState,useEffect,useCallback,useRef,Fragment} = React;

// Etapas canonicas (la clave 'key' DEBE coincidir con activity.py y la presentacion)
const STAGES = [
  {key:"detect",   label:"detect",   icon:"🧭", agent:null,                  desc:"Detecta los stacks del repo (Django, Next.js, Angular, .NET) y delimita el scope por paquete.", done:(L)=> (L.run&&L.run.stacks||[]).length>0},
  {key:"RECON",    label:"RECON",    icon:"🛰", agent:"recon-cartographer",  desc:"Mapea la superficie de ataque: entrypoints, sources/sinks y trust boundaries. Modela amenazas (STRIDE). No busca vulnerabilidades concretas.", done:(L)=> !!L.attack_surface},
  {key:"SAST",     label:"SAST",     icon:"🔬", agent:"sast-analyst",        desc:"SAST (Static Application Security Testing) del código propio (Semgrep, Bandit, ESLint-security, Roslyn). Sigue flujos source→sink con taint analysis. No escanea dependencias.", done:(L)=> (L.findings||[]).some(f=>f.sast)},
  {key:"INTEL",    label:"INTEL",    icon:"📡", agent:"threat-intel-scout",  desc:"SCA (Software Composition Analysis) de dependencias de producción. Cruza con OSV/NVD/CISA KEV/EPSS para hallar CVEs (vulnerabilidades conocidas). Solo lee fuentes oficiales.", done:(L)=> (L.findings||[]).some(f=>f.intel)},
  {key:"RED-TEAM", label:"RED-TEAM", icon:"🎯", agent:"redteam-whitehat",    desc:"Confirma la explotabilidad razonando como atacante. Produce solo PoCs (pruebas de concepto) conceptuales, nunca exploits desplegables.", done:(L)=> (L.findings||[]).some(f=>f.exploitability)},
  {key:"TRIAGE",   label:"TRIAGE",   icon:"⚖️", agent:"triage-judge",        desc:"Prioriza con CVSS + EPSS + CISA KEV, deduplica y filtra falsos positivos. KEV es override de prioridad.", done:(L)=> (L.findings||[]).some(f=>f.triage)},
  {key:"plan",     label:"plan",     icon:"🗺", agent:null,                  desc:"Genera el plan de remediación priorizado (Inmediato / Esta semana / Este mes).", done:(L)=> !!L.plan_ref},
  {key:"FIX",      label:"FIX",      icon:"🔧", agent:"appsec-fixer",        desc:"Aplica el fix de causa raíz (ASVS, Cheat Sheets) en una branch vuln-hunter/*. No commitea sin aprobación humana.", done:(L)=> (L.findings||[]).some(f=>f.fix)},
  {key:"VERIFY",   label:"VERIFY",   icon:"✅", agent:"verify-engineer",     desc:"Re-escanea el código parcheado y corre los tests. Verificación honesta: declara PARCIAL si no hay cobertura.", done:(L)=> (L.findings||[]).some(f=>f.verification)},
];

// Topologia del grafo: columna/fila por etapa. RECON se bifurca a SAST e INTEL
// (corren en paralelo) y ambas reconvergen en RED-TEAM.
const GPOS = {
  "detect":{col:0,row:1}, "RECON":{col:1,row:1},
  "SAST":{col:2,row:0}, "INTEL":{col:2,row:2},
  "RED-TEAM":{col:3,row:1}, "TRIAGE":{col:4,row:1},
  "plan":{col:5,row:1}, "FIX":{col:6,row:1}, "VERIFY":{col:7,row:1},
};
const GEDGES = [
  ["detect","RECON"],
  ["RECON","SAST"],["RECON","INTEL"],
  ["SAST","RED-TEAM"],["INTEL","RED-TEAM"],
  ["RED-TEAM","TRIAGE"],["TRIAGE","plan"],["plan","FIX"],["FIX","VERIFY"],
];
const COLW=158, NODEW=132, NODEH=58, ROWY={0:8,1:92,2:176}, GW=COLW*7+NODEW, GH=242;
const nx=(k)=>GPOS[k].col*COLW;
const ny=(k)=>ROWY[GPOS[k].row];

const PRIO = {P0:"#ef4444",P1:"#fb923c",P2:"#f59e0b",P3:"#22c55e",FILTERED:"#6b7889"};
const PRIO_ORDER = {P0:0,P1:1,P2:2,P3:3,FILTERED:9};
const STATUS_LABEL = {hypothesis:"Hipotesis",confirmed:"Confirmada",triaged:"Triada",planned:"Planificada","candidate-resolved":"Candidato a resuelto",fixed:"Corregida",closed:"Cerrada",filtered:"Filtrada"};

// ===== Glosario de abreviaciones (tooltip al pasar el cursor / enfocar) =====
const GLOSSARY = {
  SAST:{full:"SAST · Static Application Security Testing",d:"Análisis del código fuente propio sin ejecutarlo, para hallar vulnerabilidades (taint, source→sink)."},
  SCA:{full:"SCA · Software Composition Analysis",d:"Análisis de las dependencias de terceros para detectar CVEs conocidos."},
  CVE:{full:"CVE · Common Vulnerabilities and Exposures",d:"Identificador público y único de una vulnerabilidad conocida (p.ej. CVE-2024-1234)."},
  CWE:{full:"CWE · Common Weakness Enumeration",d:"Catálogo de TIPOS de debilidad de software (p.ej. CWE-89 = SQL injection)."},
  CVSS:{full:"CVSS · Common Vulnerability Scoring System",d:"Puntaje 0–10 que mide la severidad técnica de una vulnerabilidad."},
  EPSS:{full:"EPSS · Exploit Prediction Scoring System",d:"Probabilidad (0–1) de que un CVE sea explotado en los próximos 30 días."},
  KEV:{full:"CISA KEV · Known Exploited Vulnerabilities",d:"Catálogo de CISA con CVEs cuya explotación ya se confirmó in-the-wild. Es override de prioridad."},
  OWASP:{full:"OWASP · Open Worldwide Application Security Project",d:"Su Top 10 clasifica los riesgos de seguridad web más críticos."},
  GHSA:{full:"GHSA · GitHub Security Advisory",d:"Aviso de seguridad publicado por GitHub para una dependencia."},
  PoC:{full:"PoC · Proof of Concept",d:"Demostración conceptual de que una vulnerabilidad es explotable (sin exploit desplegable)."},
  ASVS:{full:"ASVS · Application Security Verification Standard",d:"Estándar OWASP de requisitos de seguridad; guía los fixes de causa raíz."},
  T1190:{full:"MITRE ATT&CK T1190",d:"«Exploit Public-Facing Application»: explotar un servicio expuesto. Vector inicial típico de ransomware."},
  SARIF:{full:"SARIF · Static Analysis Results Interchange Format",d:"Formato estándar para resultados de herramientas de análisis estático."},
  STRIDE:{full:"STRIDE · modelo de amenazas",d:"Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege."},
  SEV:{full:"Severidad / Prioridad",d:"Prioridad P0–P3 derivada de CVSS + EPSS + CISA KEV. P0 = crítico, P3 = bajo."},
};

// ===== Enlaces de justificacion: a donde apunta cada evidencia =====
const OWASP_URL = "https://owasp.org/Top10/";
const KEV_URL   = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
const EPSS_URL  = "https://www.first.org/epss/";
const T1190_URL = "https://attack.mitre.org/techniques/T1190/";
const cveUrl  = (id)=>"https://nvd.nist.gov/vuln/detail/"+encodeURIComponent(id);
const ghsaUrl = (id)=>"https://github.com/advisories/"+encodeURIComponent(id);
const cweUrl  = (cwe)=>{ const m=/(\d+)/.exec(cwe||""); return m?("https://cwe.mitre.org/data/definitions/"+m[1]+".html"):null; };

// Reune todas las referencias autoritativas que justifican un hallazgo.
function references(f){
  const intel=f.intel||{}, out=[];
  (intel.cve_ids||[]).forEach(id=>out.push({k:"CVE",label:id,url:cveUrl(id),title:"Detalle del CVE en NVD"}));
  (intel.ghsa_ids||[]).forEach(id=>out.push({k:"GHSA",label:id,url:ghsaUrl(id),title:"GitHub Security Advisory"}));
  if(f.cwe){ const u=cweUrl(f.cwe); if(u) out.push({k:"CWE",label:f.cwe,url:u,title:"Definición de la debilidad en MITRE CWE"}); }
  if(f.owasp_2025||f.owasp_2021) out.push({k:"OWASP",label:f.owasp_2025||f.owasp_2021,url:OWASP_URL,title:"OWASP Top 10"});
  if(intel.in_cisa_kev) out.push({k:"KEV",label:"CISA KEV",url:KEV_URL,title:"Catálogo CISA KEV"});
  if(intel.epss!=null) out.push({k:"EPSS",label:"EPSS "+intel.epss,url:EPSS_URL,title:"Modelo EPSS (FIRST)"});
  if(intel.known_ransomware_use) out.push({k:"ATT&CK",label:"T1190",url:T1190_URL,title:"Técnica MITRE ATT&CK T1190"});
  return out;
}

// Ciclo de vida de un hallazgo -> bucket de pestania.
const LIFE_STEPS = ["encontrados","mitigando","arreglados"];
const LIFE_LABEL = {encontrados:"Encontrado",mitigando:"Mitigando",arreglados:"Arreglado",filtrados:"Filtrado"};
function lifecycleOf(status){
  if(status==="closed") return "arreglados";
  if(status==="fixed"||status==="fixing"||status==="candidate-resolved") return "mitigando";
  if(status==="filtered") return "filtrados";
  return "encontrados";
}

async function fetchJSON(url){
  const r = await fetch(url + "?t=" + Date.now());
  if(!r.ok) throw new Error(r.status);
  return r.json();
}
async function fetchJSONL(url){
  const r = await fetch(url + "?t=" + Date.now());
  if(!r.ok) return [];
  const txt = await r.text();
  return txt.split("\n").filter(l=>l.trim()).map(l=>{ try{return JSON.parse(l)}catch(e){return null} }).filter(Boolean);
}

// Ultimo evento stage:start/stage:end de una etapa (o null si no hubo ninguno).
function lastStageEvent(stageKey, activity){
  const evs = activity.filter(e=>(e.type==="stage:start"||e.type==="stage:end") && e.stage===stageKey);
  return evs[evs.length-1] || null;
}
// Indice de la etapa que esta corriendo ahora (ultimo evento = stage:start). -1 si ninguna.
function runningStageIndex(activity){
  let r = -1;
  STAGES.forEach((s,i)=>{ const last=lastStageEvent(s.key,activity); if(last && last.type==="stage:start") r=Math.max(r,i); });
  return r;
}
// Estado de una etapa. La actividad es la verdad viva: si hay evento, manda. Sin
// eventos, cae al ledger, PERO nunca marca "done" una etapa posterior a la que
// esta corriendo (evita el contradictorio "FIX corriendo / VERIFY hecho").
function stageStatus(stage, idx, activity, ledger, runningIdx){
  const last = lastStageEvent(stage.key, activity);
  if(last) return last.type==="stage:start" ? "running" : "done";
  if(runningIdx>=0 && idx>runningIdx) return "idle";
  return stage.done(ledger) ? "done" : "idle";
}

function SevChip({p}){
  if(!p || p==="—") return null;
  return <span className="sev" style={{color:PRIO[p]||"var(--ink-mute)"}}>{p}</span>;
}

// Abreviacion con tooltip de glosario. <Gloss term="SAST">SAST</Gloss>.
function Gloss({term,children}){
  const k = term || (typeof children==="string"?children:null);
  if(!k || !GLOSSARY[k]) return <Fragment>{children!=null?children:term}</Fragment>;
  return <span className="gloss" data-term={k} tabIndex={0} role="note">{children!=null?children:term}</span>;
}
// Enlace externo de justificacion (abre en pestania nueva, con icono ↗).
function Ext({href,children,title}){
  if(!href) return <Fragment>{children}</Fragment>;
  return <a className="ext" href={href} target="_blank" rel="noopener noreferrer" title={title||"Abrir referencia"}>{children}</a>;
}

// ===== Comandos de Claude Code copiables =====
function copyText(t){
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).catch(()=>fallbackCopy(t));
  } else { fallbackCopy(t); }
}
function fallbackCopy(t){
  const ta=document.createElement("textarea"); ta.value=t;
  ta.style.position="fixed"; ta.style.opacity="0"; document.body.appendChild(ta);
  ta.select(); try{document.execCommand("copy")}catch(e){} document.body.removeChild(ta);
}
// Comando recomendado para UN hallazgo segun su estado en el ciclo de vida.
function recCommand(f){
  const life = lifecycleOf(f.status);
  if(life==="arreglados"||life==="filtrados") return null;
  if(life==="mitigando") return "/vuln-hunter:verify "+f.id;
  if(!f.exploitability) return "/vuln-hunter:redteam "+f.id;
  if(!f.triage) return "/vuln-hunter:triage";
  return "/vuln-hunter:fix "+f.id;
}
// Siguiente paso de la cadena segun el estado agregado del ledger.
function nextStep(findings){
  if(!findings.length) return "/vuln-hunter:scan";
  if(findings.some(f=>lifecycleOf(f.status)==="encontrados" && !f.exploitability)) return "/vuln-hunter:redteam all";
  if(findings.some(f=>f.exploitability && !f.triage)) return "/vuln-hunter:triage";
  if(findings.some(f=>lifecycleOf(f.status)==="encontrados")) return "/vuln-hunter:fix all";
  if(findings.some(f=>lifecycleOf(f.status)==="mitigando")) return "/vuln-hunter:verify all";
  return "/vuln-hunter:report";
}
// Boton que copia un comando con feedback visual.
function CmdChip({label,cmd,kind}){
  const [ok,setOk] = useState(false);
  if(!cmd) return null;
  const click=(e)=>{ e.stopPropagation(); copyText(cmd); setOk(true); setTimeout(()=>setOk(false),1400); };
  return (
    <button className={"cmd "+(kind||"")+(ok?" ok":"")} onClick={click} title={"Copiar: "+cmd}>
      <span className="cmd-ic">{ok?"✓":"⧉"}</span>
      {label && <span className="cmd-l">{label}</span>}
      <code className="cmd-c">{cmd}</code>
    </button>
  );
}
// Boton de copia compacto (solo icono) para una fila.
function CopyBtn({cmd}){
  const [ok,setOk] = useState(false);
  if(!cmd) return <span className="copy-na" title="Sin acción pendiente">—</span>;
  const click=(e)=>{ e.stopPropagation(); copyText(cmd); setOk(true); setTimeout(()=>setOk(false),1400); };
  return <button className={"copybtn"+(ok?" ok":"")} onClick={click} title={"Copiar: "+cmd}>{ok?"✓":"⧉"}</button>;
}
// Barra de acciones globales: status, reanudar la cadena, siguiente paso.
function ActionsBar({ledger,findings,runDone}){
  const scope = (ledger.run||{}).scope;
  const resume = "/vuln-hunter:hunt"+(scope?" "+scope:"");
  return (
    <div className="block">
      <div className="eyebrow">Acciones · copiar y pegar en Claude Code</div>
      <div className="actions-hint">Clic en cualquier comando para copiarlo al portapapeles · los comandos largos se acortan en pantalla pero se copian completos.</div>
      <div className="cmdbar">
        <CmdChip label="Siguiente paso" cmd={nextStep(findings)} kind="primary"/>
        <CmdChip label="Estado" cmd="/vuln-hunter:status"/>
        <CmdChip label="Reanudar cadena" cmd={resume}/>
      </div>
      {runDone && (
        <div className="dlrow">
          <span className="dl-l">Informe</span>
          <a className="dl" href="audit-report.html" target="_blank" rel="noopener noreferrer">📄 Abrir · imprimir PDF</a>
          <a className="dl" href="audit-report.pdf" download>⬇ PDF</a>
          <a className="dl" href="audit-report.md" download>⬇ Markdown</a>
        </div>
      )}
    </div>
  );
}

// Track visual del ciclo de vida: Encontrado -> Mitigando -> Arreglado.
function LifecycleTrack({status}){
  const cur = lifecycleOf(status);
  if(cur==="filtrados") return <span className="ltrack filtered">Filtrado (no priorizado)</span>;
  const idx = LIFE_STEPS.indexOf(cur);
  const allDone = cur==="arreglados";
  return (
    <div className="ltrack">
      {LIFE_STEPS.map((s,i)=>{
        const state = i<idx ? "past" : (i===idx ? (allDone?"done":"cur") : "future");
        return (
          <Fragment key={s}>
            {i>0 && <span className={"lbar "+(i<=idx?"on":"")}></span>}
            <span className={"lstep "+state}><span className="ld"></span>{LIFE_LABEL[s]}</span>
          </Fragment>
        );
      })}
    </div>
  );
}

function SummaryCards({findings}){
  const counts = {}; let kev=0;
  findings.forEach(f=>{
    const p = (f.triage||{}).priority || "—";
    counts[p] = (counts[p]||0)+1;
    if((f.intel||{}).in_cisa_kev) kev++;
  });
  const order = Object.keys(counts).sort((a,b)=>(PRIO_ORDER[a]??5)-(PRIO_ORDER[b]??5));
  return (
    <div className="stats">
      <div className="stat"><div className="n">{findings.length}</div><div className="l">Hallazgos</div></div>
      {order.map(p=>(
        <div className="stat" key={p}><div className="n" style={{color:PRIO[p]||"var(--cyan)"}}>{counts[p]}</div><div className="l">{p}</div></div>
      ))}
      <div className="stat"><div className="n" style={{color:"var(--amber)"}}>{kev}</div><div className="l"><Gloss term="KEV">CISA KEV</Gloss></div></div>
    </div>
  );
}

function StatusIcon({st,small}){
  const sty = small ? {width:11,height:11,fontSize:8} : null;
  if(st==="running") return <span className="ic spin" style={sty}></span>;
  if(st==="done") return <span className="ic done" style={sty}>✓</span>;
  return <span className="ic idle" style={sty}></span>;
}

// Grafo de pipeline estilo GitHub Actions. Escala al ancho del contenedor con un
// transform (sin scroll horizontal) y muestra el fork paralelo SAST/INTEL.
function PipelineGraph({activity,ledger}){
  const wrapRef = useRef(null);
  const [scale,setScale] = useState(1);
  useEffect(()=>{
    const el = wrapRef.current; if(!el) return;
    const measure = ()=>{ const w=el.clientWidth; if(w) setScale(Math.min(1, w/GW)); };
    measure();
    const ro = new ResizeObserver(measure); ro.observe(el);
    return ()=>ro.disconnect();
  },[]);
  const runningIdx = runningStageIndex(activity);
  const statusOf = {};
  STAGES.forEach((s,i)=>{ statusOf[s.key] = stageStatus(s,i,activity,ledger,runningIdx); });
  // Todas las etapas activas a la vez (soporta agentes en paralelo: SAST + INTEL).
  const runningStages = STAGES.filter(s=>statusOf[s.key]==="running");
  const runDone = activity.some(e=>e.type==="run:done");
  const blocked = activity.some(e=>e.type==="deploy:blocked");
  return (
    <div className="block surface graphwrap">
      <div className="eyebrow">Pipeline</div>
      <div className="nowline">
        {runningStages.length>0
          ? <span className="chip run"><StatusIcon st="running" small={true}/>Trabajando: {runningStages.map(s=>s.agent||s.label).join(", ")}</span>
          : <span className="chip">{runDone?"Pipeline finalizado":"Pipeline en reposo"}</span>}
        {blocked && <span className="chip block">⛔ deploy bloqueado</span>}
      </div>
      <div className="graphscroll" ref={wrapRef} style={{height:GH*scale}}>
        <div className="graph" style={{width:GW,height:GH,transform:"scale("+scale+")",transformOrigin:"top left"}}>
          <svg width={GW} height={GH} style={{position:"absolute",left:0,top:0}}>
            {GEDGES.map(([a,b],i)=>{
              const x1=nx(a)+NODEW, y1=ny(a)+NODEH/2, x2=nx(b), y2=ny(b)+NODEH/2;
              const dx=Math.max(28,(x2-x1)/2);
              const d=`M ${x1} ${y1} C ${x1+dx} ${y1}, ${x2-dx} ${y2}, ${x2} ${y2}`;
              const sa=statusOf[a], sb=statusOf[b];
              const cls = sb==="running" ? "edge active" : ((sa==="done"&&sb==="done") ? "edge done" : "edge");
              return <path key={i} className={cls} d={d}/>;
            })}
          </svg>
          {STAGES.map(s=>{
            const st = statusOf[s.key];
            const tipup = GPOS[s.key].row===2;
            return (
              <div key={s.key} className={"gnode "+st+(tipup?" tipup":"")} style={{left:nx(s.key),top:ny(s.key)}} tabIndex={0} aria-label={(s.agent||s.label)+": "+s.desc}>
                <div className="gtop"><StatusIcon st={st}/><span>{s.icon}</span><span className="glabel">{s.label}</span></div>
                <div className="gagent">{s.agent||"sin agente"} · {st}</div>
                <div className="gtip" role="tooltip">
                  <div className="gtip-h">{s.icon} {s.agent||s.label}</div>
                  <div className="gtip-b">{s.desc}</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// Bitacora viva como terminal: log cronologico (lo mas reciente abajo,
// auto-scroll) de lo que va pasando. Los hallazgos se resaltan y se enriquecen.
function Bitacora({activity,findings}){
  const ref = useRef(null);
  useEffect(()=>{ if(ref.current) ref.current.scrollTop = ref.current.scrollHeight; },[activity.length]);
  const byId = {}; findings.forEach(f=>{ byId[f.id]=f; });
  return (
    <div className="block">
      <div className="eyebrow">Bitácora · qué se va encontrando</div>
      <div className="surface terminal">
        <div className="term-bar"><span className="tdot r"></span><span className="tdot y"></span><span className="tdot g"></span><span className="ttitle">activity.jsonl · tail -f</span></div>
        <div className="blog" ref={ref}>
          {activity.length===0 && <div className="empty">Sin eventos todavía. Corre <code>/vuln-hunter:hunt</code>.</div>}
          {activity.map((e,i)=>{
            let body, cls="brow";
            if(e.type==="run:start") body=<span className="g">▶ auditoría iniciada ({e.scope||"repo"})</span>;
            else if(e.type==="run:done") body=<span className="m">■ auditoría finalizada</span>;
            else if(e.type==="stage:start") body=<span><span className="c">●</span> empieza {e.stage}{e.agent?" ("+e.agent+")":""}</span>;
            else if(e.type==="stage:end") body=<span><span className="g">✓</span> termina {e.stage}{e.summary?" · "+e.summary:""}</span>;
            else if(e.type==="finding:new"){
              cls="brow find";
              const f=byId[e.id]||{}; const p=(f.triage||{}).priority; const kev=(f.intel||{}).in_cisa_kev;
              body=(<span><span className="g">＋</span> <b>{e.id}</b> {e.title||f.title||""} {p && <SevChip p={p}/>} {kev && <span className="tag" style={{background:"var(--amber)"}}><Gloss term="KEV">KEV</Gloss></span>} <span className="src">{e.source||f.source||""}</span></span>);
            }
            else if(e.type==="finding:state"){
              const STL={fixing:"en proceso",fixed:"corregido",closed:"cerrado",filtered:"filtrado"};
              const cl={fixing:"a",fixed:"a",closed:"g",filtered:"m"}[e.state]||"c";
              body=(<span><span className={cl}>↻</span> <b>{e.id}</b> → <span className={cl}>{STL[e.state]||e.state}</span>{e.note?" · "+e.note:""}</span>);
            }
            else if(e.type==="deploy:blocked"){ cls="brow block"; body=<span className="r">⛔ deploy bloqueado · {e.reason||""}</span>; }
            else body=e.type;
            return <div className={cls} key={(e.ts||"")+e.type+(e.id||e.stage||"")+i}><span className="bt">{(e.ts||"").replace("T"," ").slice(5,16)}</span><span>{body}</span></div>;
          })}
        </div>
      </div>
    </div>
  );
}

function Facet({label,good,wide,children}){
  return (
    <div className={"facet"+(good?" good":"")+(wide?" wide":"")}>
      <div className="flabel">{label}</div>
      <div className="fval">{children}</div>
    </div>
  );
}

// Detalle enriquecido de un hallazgo: cabecera con ciclo de vida + chips, luego
// facetas (solo las que tienen datos) y la cadena de explotacion como kill-chain.
function FindingDetail({f}){
  const sast=f.sast||{}, ex=f.exploitability||{}, intel=f.intel||{}, tri=f.triage||{}, fix=f.fix||{}, ver=f.verification||{};
  const chain = ex.conceptual_chain||[];
  const refs = references(f);
  return (
    <td colSpan="8" className="detail">
      <div className="dcell">
        <div className="dhead">
          <LifecycleTrack status={f.status}/>
          <div className="dchips">
            {(f.triage||{}).priority && <span className="dchip"><b>{tri.priority}</b></span>}
            {tri.cvss!=null && <span className="dchip"><Gloss term="CVSS">CVSS</Gloss> <b>{tri.cvss}</b> v{tri.cvss_version||"?"}</span>}
            {(f.owasp_2025||f.owasp_2021) && <span className="dchip"><Ext href={OWASP_URL} title="OWASP Top 10"><Gloss term="OWASP">{f.owasp_2025||f.owasp_2021}</Gloss></Ext></span>}
            {f.cwe && <span className="dchip"><Ext href={cweUrl(f.cwe)} title="MITRE CWE"><Gloss term="CWE">{f.cwe}</Gloss></Ext></span>}
            {f.source && <span className="dchip">{f.source}</span>}
          </div>
        </div>
        <div className="dcmds">
          <span className="dcmds-l">Atacar {f.id}:</span>
          <CmdChip label="recomendado" cmd={recCommand(f)} kind="primary"/>
          <CmdChip cmd={"/vuln-hunter:redteam "+f.id}/>
          <CmdChip cmd={"/vuln-hunter:fix "+f.id}/>
          <CmdChip cmd={"/vuln-hunter:verify "+f.id}/>
        </div>
        <div className="facets">
          <Facet label="📍 Ubicación"><code>{f.location||"—"}</code></Facet>
          {sast.hypothesis && <Facet label="🧠 Hipótesis">{sast.hypothesis}</Facet>}
          {sast.flow && <Facet label="🔬 Flujo SAST"><code>{sast.flow}</code> · confianza {sast.confidence??"—"} · {sast.tool||""}</Facet>}
          {intel.package && <Facet label="📡 Dependencia">
            <code>{intel.package}@{intel.installed_version}</code> → fix {intel.fixed_version||"?"}
            {(intel.cve_ids||[]).length>0 && <Fragment> · {intel.cve_ids.map((id,i)=><Fragment key={id}>{i>0?", ":""}<Ext href={cveUrl(id)} title="Detalle en NVD">{id}</Ext></Fragment>)}</Fragment>}
            {intel.in_cisa_kev && <Fragment> · <Ext href={KEV_URL} title="Catálogo CISA KEV"><Gloss term="KEV">KEV</Gloss></Ext></Fragment>}
            {intel.epss!=null && <Fragment> · <Gloss term="EPSS">EPSS</Gloss> <Ext href={EPSS_URL} title="Modelo EPSS (FIRST)">{intel.epss}</Ext></Fragment>}
          </Facet>}
          {ex.verdict && <Facet label="🎯 Explotabilidad">{ex.verdict}{ex.conditions?" · "+ex.conditions:""}</Facet>}
          {tri.rationale && <Facet label="⚖️ Triage">{tri.priority} · {tri.rationale}</Facet>}
          {fix.root_cause && <Facet label="🔧 Fix (causa raíz)" good={!!fix.applied}>{fix.root_cause} → {fix.summary||""} {fix.asvs?<Fragment>· <Gloss term="ASVS">ASVS</Gloss> {fix.asvs}</Fragment>:""} {fix.applied? <span className="ok">· aplicado al working tree</span> : "· sin aplicar"}</Facet>}
          {ver.verdict && <Facet label="✅ Verificación" good={ver.verdict==="CLOSED"}>{ver.verdict}{ver.evidence?" · "+ver.evidence:""}</Facet>}
          {refs.length>0 && <Facet label="🔗 Referencias (justificación)" wide={true}>
            <div className="refs">{refs.map((r,i)=><a key={i} className="refchip" href={r.url} target="_blank" rel="noopener noreferrer" title={r.title}><span className="rk">{r.k}</span>{r.label}</a>)}</div>
          </Facet>}
        </div>
        {chain.length>0 && (
          <Facet label="🧨 Cadena de explotación (PoC conceptual)" wide={true}>
            <ol className="killchain">
              {chain.map((c,i)=><li key={i}><span className="kn">{i+1}</span><span className="kt">{c}</span></li>)}
            </ol>
          </Facet>
        )}
      </div>
    </td>
  );
}

function FindingsTable({findings,bucket}){
  const [open,setOpen] = useState({});
  const [sel,setSel] = useState(()=>new Set());
  const EMPTY = {encontrados:"Sin hallazgos abiertos en este momento.",mitigando:"Nada en mitigación todavía.",arreglados:"Aún no hay hallazgos resueltos.",filtrados:"Sin hallazgos filtrados."};
  const sorted = [...findings].sort((a,b)=>(PRIO_ORDER[(a.triage||{}).priority]??5)-(PRIO_ORDER[(b.triage||{}).priority]??5));
  if(findings.length===0) return <div className="empty">{EMPTY[bucket]||"Sin hallazgos."}</div>;
  const toggleSel=(id,e)=>{ e.stopPropagation(); setSel(s=>{ const n=new Set(s); n.has(id)?n.delete(id):n.add(id); return n; }); };
  const ids=[...sel];
  return (
    <Fragment>
      {ids.length>0 && (
        <div className="seltool">
          <span className="seln"><b>{ids.length}</b> seleccionado{ids.length>1?"s":""} · <code>{ids.join(" ")}</code></span>
          <div className="selcmds">
            <CmdChip label="Red-team" cmd={"/vuln-hunter:redteam "+ids.join(" ")}/>
            <CmdChip label="Fix" cmd={"/vuln-hunter:fix "+ids.join(" ")} kind="primary"/>
            <CmdChip label="Verify" cmd={"/vuln-hunter:verify "+ids.join(" ")}/>
            <button className="selclear" onClick={()=>setSel(new Set())}>limpiar</button>
          </div>
        </div>
      )}
      <table>
        <thead><tr><th className="csel"></th><th>ID</th><th><Gloss term="SEV">Sev</Gloss></th><th>Titulo</th><th><Gloss term="OWASP">OWASP</Gloss> / <Gloss term="CWE">CWE</Gloss></th><th>Explotable</th><th>Estado</th><th>Acción</th></tr></thead>
        <tbody className="swap" key={bucket}>
          {sorted.map(f=>{
            const p = (f.triage||{}).priority || "—";
            const intel = f.intel||{};
            const isOpen = !!open[f.id];
            const life = lifecycleOf(f.status);
            const checked = sel.has(f.id);
            return (
              <Fragment key={f.id}>
                <tr className={"frow "+life+(checked?" sel":"")+(f.status==="fixing"?" active":"")} onClick={()=>setOpen(o=>({...o,[f.id]:!o[f.id]}))}>
                  <td className="csel" onClick={(e)=>e.stopPropagation()}><input type="checkbox" checked={checked} onChange={()=>{}} onClick={(e)=>toggleSel(f.id,e)} aria-label={"seleccionar "+f.id}/></td>
                  <td><code>{f.id}</code></td>
                  <td>{p!=="—" ? <SevChip p={p}/> : "—"}</td>
                  <td>{f.title} {intel.in_cisa_kev && <span className="tag" style={{background:"var(--amber)"}}><Gloss term="KEV">KEV</Gloss></span>} {intel.known_ransomware_use && <span className="tag" style={{background:"var(--red)"}}>RANSOMWARE</span>}
                    {bucket==="arreglados" && (f.fix||f.verification) && <div className="fixed-what">✓ {(f.fix||{}).summary||(f.fix||{}).root_cause||"corregido"}{(f.verification||{}).evidence?" · "+f.verification.evidence:""}</div>}
                  </td>
                  <td>{f.owasp_2025||f.owasp_2021||"—"}<br/><span style={{color:"var(--ink-mute)",fontSize:12}}>{f.cwe||""}</span></td>
                  <td>{(f.exploitability||{}).verdict||"—"}</td>
                  <td>{f.status==="fixing" ? <span className="lbadge active">En proceso</span> : <span className={"lbadge "+life}>{LIFE_LABEL[life]}</span>}</td>
                  <td onClick={(e)=>e.stopPropagation()}><CopyBtn cmd={recCommand(f)}/></td>
                </tr>
                {isOpen && <tr><FindingDetail f={f}/></tr>}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </Fragment>
  );
}

// Hallazgos con pestanias por ciclo de vida. Un hallazgo se mueve de pestania
// (Encontrados -> Mitigando -> Arreglados) conforme se arregla: ese es el cambio
// de estado visible.
function FindingsPanel({findings}){
  const buckets = {encontrados:[],mitigando:[],arreglados:[],filtrados:[]};
  findings.forEach(f=>{ buckets[lifecycleOf(f.status)].push(f); });
  const tabs = [["encontrados","Encontrados"],["mitigando","Mitigando"],["arreglados","Arreglados"]];
  if(buckets.filtrados.length) tabs.push(["filtrados","Filtrados"]);
  const [tab,setTab] = useState("encontrados");
  const active = buckets[tab] ? tab : "encontrados";
  return (
    <div className="block">
      <div className="eyebrow">Hallazgos</div>
      <div className="tabs">
        {tabs.map(([k,lbl])=>(
          <button key={k} className={"tab "+(active===k?"on":"")} onClick={()=>setTab(k)}>
            <span className={"tdot "+k}></span>{lbl}<span className="tcount">{buckets[k].length}</span>
          </button>
        ))}
      </div>
      <div className="surface tablecard"><FindingsTable findings={buckets[active]||[]} bucket={active}/></div>
    </div>
  );
}

// Etiqueta corta de una corrida del historial para el selector.
function runShort(r){
  const when = (r.started_at||r.id||"").replace("T"," ").slice(0,16);
  const p0 = (r.by_prio||{}).P0||0;
  return (r.scope||"repo")+" · "+when+" · P0:"+p0+"/"+(r.total||0)+" · "+(r.verdict||"—");
}

// Selector de corridas: "En vivo" + historicas (solo lectura).
function RunSelector({runs,view,setView}){
  if(!runs || !runs.length) return null;
  return (
    <div className="block" style={{display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}>
      <span className="eyebrow" style={{margin:0}}>Corridas</span>
      <select value={view} onChange={e=>setView(e.target.value)}
        style={{fontFamily:"var(--mono)",fontSize:"12.5px",background:"var(--bg-2)",color:"var(--ink)",
                border:"1px solid var(--line-2)",borderRadius:"9px",padding:"7px 10px",cursor:"pointer",maxWidth:"100%"}}>
        <option value="live">● En vivo (corrida actual)</option>
        {runs.slice().reverse().map(r=>(
          <option key={r.id} value={r.id}>{runShort(r)}</option>
        ))}
      </select>
      {view!=="live" && <span className="chip" style={{borderColor:"var(--amber)",color:"var(--amber)"}}>⏱ histórico · solo lectura</span>}
    </div>
  );
}

function App(){
  const [ledger,setLedger] = useState(null);
  const [activity,setActivity] = useState([]);
  const [err,setErr] = useState(null);
  const [updated,setUpdated] = useState(null);
  const [runs,setRuns] = useState(null);   // historial (history/index.json) o null
  const [view,setView] = useState("live");  // "live" o id de una corrida pasada

  // carga el indice del historial (best-effort; si no existe, no pasa nada)
  useEffect(()=>{ fetchJSON("history/index.json").then(r=>{ if(Array.isArray(r)) setRuns(r); }).catch(()=>{}); },[]);

  const isLive = view==="live";
  const base = isLive ? "" : ("history/"+view+"/");
  const poll = useCallback(async ()=>{
    try{
      const L = await fetchJSON(base+"ledger.json");
      const A = await fetchJSONL(base+"activity.jsonl");
      setLedger(L); setActivity(A); setErr(null);
      setUpdated(new Date().toLocaleTimeString());
    }catch(e){ setErr(String(e)); }
  },[base]);

  // Live: polling cada 2s. Historico: snapshot estatico -> una sola carga.
  useEffect(()=>{
    poll();
    if(!isLive) return;
    const id=setInterval(poll,2000); return ()=>clearInterval(id);
  },[poll,isLive]);

  // Tooltip de glosario: un solo elemento fijo posicionado en hover/focus de .gloss
  // (position:fixed -> no lo recortan los contenedores con overflow:hidden, como las tablas).
  useEffect(()=>{
    let tip = document.getElementById("glosstip");
    if(!tip){ tip = document.createElement("div"); tip.id = "glosstip"; document.body.appendChild(tip); }
    const show = (el)=>{
      const g = GLOSSARY[el.getAttribute("data-term")]; if(!g) return;
      tip.innerHTML = "";
      const h = document.createElement("div"); h.className = "gt-h"; h.textContent = g.full;
      const b = document.createElement("div"); b.textContent = g.d;
      tip.appendChild(h); tip.appendChild(b);
      tip.style.left = "0px"; tip.style.top = "0px"; tip.classList.add("on");
      const r = el.getBoundingClientRect();
      const tw = tip.offsetWidth, th = tip.offsetHeight;
      const left = Math.min(window.innerWidth - tw - 8, Math.max(8, r.left));
      let top = r.bottom + 8;
      if(top + th > window.innerHeight - 8) top = Math.max(8, r.top - th - 8);
      tip.style.left = left + "px"; tip.style.top = top + "px";
    };
    const hide = ()=>tip.classList.remove("on");
    const over = (e)=>{ const el = e.target && e.target.closest && e.target.closest(".gloss"); if(el) show(el); };
    const out  = (e)=>{ const el = e.target && e.target.closest && e.target.closest(".gloss"); if(el) hide(); };
    document.addEventListener("mouseover", over);
    document.addEventListener("mouseout", out);
    document.addEventListener("focusin", over);
    document.addEventListener("focusout", out);
    window.addEventListener("scroll", hide, true);
    return ()=>{
      document.removeEventListener("mouseover", over);
      document.removeEventListener("mouseout", out);
      document.removeEventListener("focusin", over);
      document.removeEventListener("focusout", out);
      window.removeEventListener("scroll", hide, true);
    };
  },[]);

  if(err && !ledger) return <div className="wrap"><div className="brand"><span className="slash">//</span>vuln-hunter</div><div className="surface empty">No se pudo leer <code>ledger.json</code> ({err}). Corre <code>/vuln-hunter:detect</code> o <code>/vuln-hunter:hunt</code> primero.</div></div>;
  if(!ledger) return <div className="wrap"><div className="surface empty">Cargando…</div></div>;

  const run = ledger.run||{};
  const findings = ledger.findings||[];
  const runDone = activity.some(e=>e.type==="run:done");
  const kev = findings.filter(f=>(f.intel||{}).in_cisa_kev).length;

  const showLive = isLive && !runDone;
  return (
    <div className="wrap">
      <div className="brand">
        {showLive && <span className="bdot"></span>}vuln-hunter<span className="slash">//</span>panel {isLive?"vivo":"histórico"}
        {showLive && <span className="liveword">live</span>}
      </div>
      <div className="sub">scope: <b>{run.scope||"repo completo"}</b> · branch: {run.branch||"—"} · OWASP {run.owasp_version||"2025"} · stacks: {(run.stacks||[]).join(", ")||"—"} · {isLive?(runDone?"finalizada":"en curso"):"corrida archivada"} · act {updated||"—"}</div>

      <RunSelector runs={runs} view={view} setView={setView}/>

      {kev>0 && <div className="alert"><span className="aic">⚠</span><div className="atxt"><b>Atención:</b> {kev} dependencia(s) de producción con <Gloss term="CVE">CVE</Gloss> en <Ext href={KEV_URL} title="Catálogo CISA KEV"><Gloss term="KEV">CISA KEV</Gloss></Ext>. El deploy queda bloqueado hasta parchear (vector típico de ransomware, <Ext href={T1190_URL} title="MITRE ATT&CK"><Gloss term="T1190">MITRE T1190</Gloss></Ext>).</div></div>}

      <SummaryCards findings={findings}/>
      <ActionsBar ledger={ledger} findings={findings} runDone={runDone}/>
      <PipelineGraph activity={activity} ledger={ledger}/>
      <Bitacora activity={activity} findings={findings}/>
      <FindingsPanel findings={findings}/>

      <footer>Datos: <b>.vuln-hunter/ledger.json</b> + <b>activity.jsonl</b> · historial en <b>.vuln-hunter/history/</b> (selector arriba) · panel estático loopback · vuln-hunter no sustituye auditoría humana.</footer>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App/>);
