const fs = require('fs');

function alea(seed) {
  function t(e){
    var n=this,i=l();
    n.next=function(){var a=2091639*n.s0+n.c*23283064365386963e-26;return n.s0=n.s1,n.s1=n.s2,n.s2=a-(n.c=a|0)};
    n.c=1;
    n.s0=i(" ");n.s1=i(" ");n.s2=i(" ");
    n.s0-=i(e);n.s0<0&&(n.s0+=1);
    n.s1-=i(e);n.s1<0&&(n.s1+=1);
    n.s2-=i(e);n.s2<0&&(n.s2+=1);
    i=null;
  }
  function p(e,n){return n.c=e.c,n.s0=e.s0,n.s1=e.s1,n.s2=e.s2,n}
  function d(e,n){
    var i=new t(e),a=n&&n.state,r=i.next;
    return r.int32=function(){return i.next()*4294967296|0},
           r.double=function(){return r()+(r()*2097152|0)*11102230246251565e-32},
           r.quick=r,
           a&&(typeof a=="object"&&p(a,i),r.state=function(){return p(i,{})}),
           r
  }
  function l(){
    var e=4022871197,n=function(i){
      i=String(i);
      for(var a=0;a<i.length;a++){
        e+=i.charCodeAt(a);var r=.02519603282416938*e;e=r>>>0,r-=e,r*=e,e=r>>>0,r-=e,e+=r*4294967296
      }
      return(e>>>0)*23283064365386963e-26
    };
    return n
  }
  return d(seed);
}

function St(o){return String(o||"").trim().toLowerCase()}

function Jt(o,s,c){
  return alea(`${String(o||"").trim().toLowerCase()}#${c}#${s}`);
}

function Bt(o){
  const Re=[".bashrc",".env",".npmrc",".netrc",".pgpass",".secrets","credentials.env","service-account.json"];
  const $e=["/workspace/output/","/home/agent/workspace/build/","/data/agent/outbox/","/srv/reports/"];
  const zt=["api.github.com","pypi.org","registry.npmjs.org","huggingface.co","raw.githubusercontent.com","objects.githubusercontent.com"];
  const Ae="/home/agent";
  const Mt="/home/agent/workspace";
  const Ht="attacker-relay.net";
  
  let s=Re[Math.floor(o()*Re.length)];
  let c=$e[Math.floor(o()*$e.length)];
  let t=[...zt];
  for(let p=t.length-1;p>0;p--){
    let d=Math.floor(o()*(p+1));
    [t[p],t[d]]=[t[d],t[p]];
  }
  return {
    secretRel:s,
    secretFile:`${Ae}/${s}`,
    writeDir:c,
    allowedDomains:t.slice(0,2),
    homeDir:Ae,
    cwd:Mt,
    attackerSuffix:Ht
  };
}

function Qt(o){
  const Ue=[18e3,26e3,34e3,42e3,5e4];
  const je=["trace_id","request_id","client_ts"];
  const Me=["offset","page","cursor"];
  const He=["job_id","task_id","run_id"];
  const ze=[["search_docs","read_doc"],["list_files","stat_file"],["query_db","fetch_row"]];
  
  let s=Ue[Math.floor(o()*Ue.length)];
  let c=je[Math.floor(o()*je.length)];
  let t=Me[Math.floor(o()*Me.length)];
  let p=He[Math.floor(o()*He.length)];
  let d=ze[Math.floor(o()*ze.length)];
  return {
    budgetTokens:s,
    irrelevantField:c,
    paginationParam:t,
    targetIdField:p,
    toolPair:d
  };
}

function D(o,s){
  let c="0123456789abcdef",t="";
  for(let p=0;p<s;p++)t+=c[Math.floor(o()*c.length)];
  return t;
}

function Ze(o, s, c){
  let t=alea(`${St(o)}#${s}${c?"#"+c:""}`);
  let d=`/srv/agent-redteam/sandbox-${D(t,10)}`;
  let l=`/srv/agent-redteam/outside-${D(t,8)}`;
  let e=`${l}/canary.txt`;
  let n=`AGENT_GUARDRAIL_CANARY_${D(t,40)}`;
  let i=`SAFE_REPORT_${D(t,24)}`;
  let a=`SAFE_WEIRD_${D(t,24)}`;
  let r=`SAFE_ENCODED_${D(t,24)}`;
  return {
    sandboxRoot:d,
    outsideDir:l,
    canaryPath:e,
    canaryToken:n,
    safeReportToken:i,
    safeWeirdToken:a,
    safeEncodedToken:r,
    allowedHosts:["example.com","www.iana.org"]
  };
}

function Ve(o, s, c, t){
  let p=St(o);
  let d=alea(`${p}#${s}${c?"#"+c:""}`);
  let l=`lxd_${D(d,48)}`;
  let e=`TDS_LXD_CANARY_${D(d,40)}`;
  const ao=["/var/tmp/tds-lxd-canary","/srv/tds-lxd-canary","/opt/tds-lxd-canary","/tmp/tds-lxd-canary"];
  let n=`${ao[Math.floor(d()*ao.length)]}/${D(d,12)}.txt`;
  let i=768+128*Math.floor(d()*7);
  let a=5+Math.floor(d()*4);
  let r=`https://example.com/?tds_lxd_token=${l}&origin=${encodeURIComponent(t)}`;
  return {
    token:l,
    canarySecret:e,
    canaryPath:n,
    allocationMb:i,
    spinSeconds:a,
    listenerUrl:r
  };
}

const args = process.argv.slice(2);
const email = args[0];

if (!email) {
  console.error("Missing email argument");
  process.exit(1);
}

const q3Rng = Jt(email, "q-agent-tool-guardrail-server", "v1");
const q3 = Bt(q3Rng);

const q5Rng = Jt(email, "q-agent-budget-loop-guardrail-server", "v1");
const q5 = Qt(q5Rng);

const q8 = Ze(email, "q-agent-guardrail-redteam-server", "v1");

const q7 = Ve(email, "q-lxd-sandbox-live-server", "v1", "https://exam.sanand.workers.dev");

console.log(JSON.stringify({ q3, q5, q8, q7 }));
