/* LAN Sentinel browser-side traffic analyzer. No server, Python, Node.js, or external library. */
(function(global){
  'use strict';
  const num=v=>{const n=Number(v);return Number.isFinite(n)?n:0;};
  const clean=v=>String(v==null?'':v).trim();
  function parseCSV(text){
    const rows=[];let row=[],cell='',quoted=false;
    for(let i=0;i<text.length;i++){const c=text[i];if(quoted){if(c==='"'&&text[i+1]==='"'){cell+='"';i++;}else if(c==='"')quoted=false;else cell+=c;}else if(c==='"')quoted=true;else if(c===','){row.push(cell);cell='';}else if(c==='\n'){row.push(cell);if(row.some(x=>clean(x)))rows.push(row);row=[];cell='';}else if(c!=='\r')cell+=c;}
    row.push(cell);if(row.some(x=>clean(x)))rows.push(row);if(rows.length<2)throw Error('CSV needs a header row and at least one data row.');
    const headers=rows.shift().map(h=>clean(h).toLowerCase().replace(/[\s-]+/g,'_'));
    const alias={source_ip:'src_ip',src:'src_ip',destination_ip:'dst_ip',dst:'dst_ip',source_port:'src_port',destination_port:'dst_port',length:'bytes',packet_length:'bytes',frame_length:'bytes',flags:'tcp_flags',mac:'src_mac',source_mac:'src_mac',timestamp_utc:'timestamp',time:'timestamp',proto:'protocol'};
    const records=rows.map(r=>{const o={};headers.forEach((h,i)=>o[alias[h]||h]=clean(r[i]));return normalize(o);}).filter(r=>r.src_ip||r.dst_ip||r.src_mac||r.arp_sender_ip);
    if(!records.length)throw Error('No usable traffic rows. Include src_ip/dst_ip or ARP sender fields.');return records;
  }
  function normalize(o){return {timestamp:clean(o.timestamp)||new Date().toISOString(),src_ip:clean(o.src_ip),dst_ip:clean(o.dst_ip),src_port:num(o.src_port),dst_port:num(o.dst_port),protocol:clean(o.protocol).toUpperCase()||'OTHER',bytes:num(o.bytes),tcp_flags:clean(o.tcp_flags).toUpperCase(),src_mac:clean(o.src_mac).toUpperCase(),dst_mac:clean(o.dst_mac).toUpperCase(),arp_sender_ip:clean(o.arp_sender_ip),arp_sender_mac:clean(o.arp_sender_mac||o.src_mac).toUpperCase()};}
  function parsePCAP(buffer){
    const view=new DataView(buffer),u8=new Uint8Array(buffer);if(buffer.byteLength<24)throw Error('Capture is too short to be a valid PCAP file.');
    const magic=[...u8.slice(0,4)].map(x=>x.toString(16).padStart(2,'0')).join('');
    if(magic==='0a0d0d0a')return parsePCAPNG(view,u8);
    const little=magic==='d4c3b2a1'||magic==='4d3cb2a1';const nano=magic==='a1b23c4d'||magic==='4d3cb2a1';
    if(!['d4c3b2a1','a1b2c3d4','4d3cb2a1','a1b23c4d'].includes(magic))throw Error('Unsupported capture format. Use classic PCAP or PCAPNG.');
    const link=view.getUint32(20,little);if(link!==1)throw Error('This PCAP link type is not Ethernet. Export an Ethernet PCAP.');
    const out=[];let off=24;
    while(off+16<=view.byteLength){const sec=view.getUint32(off,little),frac=view.getUint32(off+4,little),incl=view.getUint32(off+8,little);off+=16;if(incl>view.byteLength-off)break;const packet=u8.subarray(off,off+incl);off+=incl;const r=decodeEthernet(packet);if(r){r.timestamp=new Date(sec*1000+frac/(nano?1e6:1e3)).toISOString();r.bytes=incl;out.push(normalize(r));}}
    if(!out.length)throw Error('No supported Ethernet IPv4, IPv6, or ARP packets were found in this capture.');return out;
  }
  function parsePCAPNG(view,u8){
    let off=0,little=true,link=1;const out=[];
    while(off+12<=view.byteLength){const type=view.getUint32(off,true);let len=view.getUint32(off+4,little);if(type===0x0a0d0d0a){const bom=view.getUint32(off+8,true);little=bom===0x1a2b3c4d;len=view.getUint32(off+4,little);}if(len<12||off+len>view.byteLength)break;
      if(type===1&&len>=20)link=view.getUint16(off+8,little);
      if(type===6&&len>=32&&link===1){const hi=view.getUint32(off+12,little),lo=view.getUint32(off+16,little),cap=view.getUint32(off+20,little),start=off+28;if(cap<=len-32&&start+cap<=off+len-4){const r=decodeEthernet(u8.subarray(start,start+cap));if(r){r.timestamp=new Date((hi*4294967296+lo)/1000).toISOString();r.bytes=cap;out.push(normalize(r));}}}
      off+=len;
    }
    if(!out.length)throw Error('No supported Ethernet packets found in PCAPNG.');return out;
  }
  function mac(b,o){return [...b.subarray(o,o+6)].map(x=>x.toString(16).padStart(2,'0')).join(':').toUpperCase();}
  function ip(b,o){return [...b.subarray(o,o+4)].join('.');}
  function decodeEthernet(b){if(b.length<14)return null;const dst=mac(b,0),src=mac(b,6);let et=(b[12]<<8)|b[13],o=14;while(et===0x8100||et===0x88a8){if(b.length<o+4)return null;et=(b[o+2]<<8)|b[o+3];o+=4;}
    if(et===0x0806&&b.length>=o+28){return {protocol:'ARP',src_mac:src,dst_mac:dst,arp_sender_ip:ip(b,o+14),arp_sender_mac:mac(b,o+8)};}
    if(et===0x0800&&b.length>=o+20){const ihl=(b[o]&15)*4;if(b.length<o+ihl)return null;const proto=b[o+9],s=ip(b,o+12),d=ip(b,o+16);let sp=0,dp=0,flags='';if((proto===6||proto===17)&&b.length>=o+ihl+4){sp=(b[o+ihl]<<8)|b[o+ihl+1];dp=(b[o+ihl+2]<<8)|b[o+ihl+3];}if(proto===6&&b.length>=o+ihl+14){const f=b[o+ihl+13];flags=(f&2?'S':'')+(f&16?'A':'')+(f&1?'F':'')+(f&4?'R':'');}return {protocol:proto===6?'TCP':proto===17?'UDP':proto===1?'ICMP':'IP',src_ip:s,dst_ip:d,src_port:sp,dst_port:dp,tcp_flags:flags,src_mac:src,dst_mac:dst};}
    if(et===0x86dd&&b.length>=o+40){const proto=b[o+6],s=[...b.subarray(o+8,o+24)].map(x=>x.toString(16).padStart(2,'0')).join('').match(/.{1,4}/g).join(':'),d=[...b.subarray(o+24,o+40)].map(x=>x.toString(16).padStart(2,'0')).join('').match(/.{1,4}/g).join(':');return {protocol:proto===6?'TCP':proto===17?'UDP':'IPv6',src_ip:s,dst_ip:d,src_mac:src,dst_mac:dst};}return null;
  }
  function analyze(records,opts={}){
    const alerts=[],portMap=new Map(),synMap=new Map(),arpMap=new Map(),devices=new Map();
    records.forEach((r,i)=>{const t=Date.parse(r.timestamp)||i*1000;if(r.src_ip){const k=r.src_ip+'|'+r.src_mac;if(!devices.has(k))devices.set(k,{ip:r.src_ip,mac:r.src_mac||'Not present',packets:0,bytes:0,protocols:new Set()});const d=devices.get(k);d.packets++;d.bytes+=r.bytes;d.protocols.add(r.protocol);}
      if(r.protocol==='TCP'&&r.src_ip&&r.dst_port){const k=r.src_ip; if(!portMap.has(k))portMap.set(k,[]);portMap.get(k).push({port:r.dst_port,t});if(r.tcp_flags.includes('S')&&!r.tcp_flags.includes('A')){if(!synMap.has(k))synMap.set(k,[]);synMap.get(k).push(t);}}
      if(r.protocol==='ARP'&&r.arp_sender_ip&&r.arp_sender_mac){if(!arpMap.has(r.arp_sender_ip))arpMap.set(r.arp_sender_ip,new Set());arpMap.get(r.arp_sender_ip).add(r.arp_sender_mac);}
    });
    const add=(category,severity,source,evidence,method)=>alerts.push({id:'LS-'+String(alerts.length+1).padStart(3,'0'),category,severity,source,evidence,method,status:'Needs review',confidence:null});
    for(const [src,items] of portMap){const ports=new Set(items.map(x=>x.port));if(ports.size>=15){const span=Math.max(...items.map(x=>x.t))-Math.min(...items.map(x=>x.t));add('Port-scan indicator','High',src,`${ports.size} distinct destination TCP ports observed from this source across ${items.length} records (${Math.round(span/1000)} seconds).`, 'Transparent rule: >=15 unique destination TCP ports');}}
    for(const [src,times] of synMap){const sorted=times.slice().sort((a,b)=>a-b);let max=0,left=0;for(let right=0;right<sorted.length;right++){while(sorted[right]-sorted[left]>10000)left++;max=Math.max(max,right-left+1);}if(max>=100)add('SYN-flood indicator','High',src,`${max} TCP SYN packets in a rolling 10-second window.`, 'Transparent rule: >=100 SYN packets / 10 seconds');}
    for(const [sender,macs] of arpMap){if(macs.size>1)add('Conflicting ARP identity','High',sender,`ARP sender IP ${sender} appeared with ${macs.size} different sender MAC addresses: ${[...macs].join(', ')}.`, 'ARP consistency rule: one sender IP mapped to multiple MACs');}
    const protocols={};records.forEach(r=>protocols[r.protocol]=(protocols[r.protocol]||0)+1);
    const bytes=records.reduce((s,r)=>s+r.bytes,0),uniqueSrc=new Set(records.map(r=>r.src_ip).filter(Boolean)).size;
    let ml={loaded:false,result:null,reason:'No trained model loaded. Rule analysis is active; ML inference is unavailable.'};
    if(opts.model){ml=runModel(opts.model,{packet_count:records.length,unique_source_ips:uniqueSrc,unique_destination_ports:new Set(records.map(r=>r.dst_port).filter(Boolean)).size,mean_packet_bytes:records.length?bytes/records.length:0,tcp_ratio:(protocols.TCP||0)/records.length,syn_count:records.filter(r=>r.protocol==='TCP'&&r.tcp_flags.includes('S')&&!r.tcp_flags.includes('A')).length});}
    return {records:records.length,devices:[...devices.values()].map(d=>({...d,protocols:[...d.protocols]})),alerts,protocols,bytes,uniqueSources:uniqueSrc,ml,summary:{tcp:protocols.TCP||0,udp:protocols.UDP||0,arp:protocols.ARP||0,other:records.length-(protocols.TCP||0)-(protocols.UDP||0)-(protocols.ARP||0)}};
  }
  function runModel(model,features){try{if(model.format!=='lan-sentinel-logistic-v1'||!Array.isArray(model.features)||!model.weights||!Number.isFinite(Number(model.bias)))throw Error('Model JSON schema is not LAN Sentinel logistic v1.');let z=Number(model.bias);model.features.forEach(f=>{const value=num(features[f.name]);const scale=num(f.scale)||1;z+=((value-num(f.mean))/scale)*num(model.weights[f.name]);});const score=1/(1+Math.exp(-Math.max(-30,Math.min(30,z))));const validated=model.validated===true&&!!(model.validation&&model.validation.dataset&&model.validation.metrics);return {loaded:true,validated,result:score,threshold:num(model.threshold)||0.7,reason:validated?'Local inference from a model declaring validation metadata. Independently confirm the model evaluation before relying on it.':'Model loaded but has no validation metadata. Its score is experimental and must not be treated as a verified AI detection.'};}catch(e){return {loaded:false,result:null,reason:e.message};}}
  global.LANSentinelAnalyzer={parseCSV,parsePCAP,analyze};
})(window);
