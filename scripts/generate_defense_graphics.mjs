/** Original, dependency-free SVG walkthrough for the README and landing page. */
import {mkdirSync, writeFileSync} from 'node:fs';
import {dirname, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const output = resolve(dirname(fileURLToPath(import.meta.url)), '../docs/assets');
mkdirSync(output, {recursive: true});
const text = (x,y,value,classes='cg-body',anchor='start') => `<text x="${x}" y="${y}" class="${classes}" text-anchor="${anchor}">${value}</text>`;
const rect = (x,y,w,h,classes='cg-panel') => `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="6" class="${classes}"/>`;
const phase = (number, content) => `<g class="cg-phase cg-phase-${number}">${content}</g>`;
const chip = (x,y,w,label,classes='') => `<g class="${classes}">${rect(x,y,w,34,'cg-chip')}${text(x+12,y+23,label,'cg-code')}</g>`;

function graphic(mobile) {
  const id = mobile ? 'cg-mobile' : 'cg-desktop';
  const W=mobile?480:1120, H=mobile?730:520;
  const L={x:mobile?16:28,y:28,w:mobile?198:280,h:mobile?228:288};
  const R={...L,x:mobile?266:812};
  const P={x:mobile?130:422,y:mobile?326:85,w:mobile?220:276,h:230};
  const B={x:L.x,y:mobile?600:375,w:L.w,h:96};
  const V={x:mobile?266:422,y:B.y,w:mobile?198:670,h:96};
  const publishStart={x:mobile?115:308,y:mobile?273:194};
  const publishMove=mobile?'65px, 39px':'104px, 0px';
  const probeStart={x:mobile?326:716,y:mobile?285:194};
  const probeMove=mobile?'-20px, 30px':'-62px, 0px';
  const publicStart={x:mobile?274:720,y:mobile?309:251};
  const publicMove=mobile?'48px, -43px':'82px, 0px';
  const css=`
    .cg-bg{fill:#f8f9f6}.cg-panel{fill:#f8f9f6;stroke:#cdd6c7;stroke-width:1.4}.cg-owner{fill:#e5ecdf;stroke:#b6c7af;stroke-width:1.4}.cg-release{fill:#fff;stroke:#315b3c;stroke-width:1.8}.cg-chip{fill:#eff2ec;stroke:#d4ddcd}.cg-title,.cg-body,.cg-small,.cg-label{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;fill:#20251f}.cg-title{font-size:26px;font-weight:600;letter-spacing:-.6px}.cg-body{font-size:19px}.cg-small{font-size:16px;fill:#62695f}.cg-label{font-size:17px;fill:#315b3c;font-weight:600}.cg-code{font:16px 'SFMono-Regular',Consolas,monospace;fill:#315b3c}.cg-divider,.cg-wire{fill:none;stroke:#c3cdbd;stroke-width:1.5}.cg-wire{stroke-dasharray:5 6}.cg-packet rect{fill:#315b3c;stroke:#315b3c}.cg-packet text{fill:#fff;font:15px 'SFMono-Regular',Consolas,monospace}.cg-probe rect{fill:#62695f;stroke:#62695f}.cg-phase{opacity:0}.cg-phase-3{opacity:1}.cg-source-private{opacity:0}.cg-private-files{opacity:1}.cg-packet{opacity:0}.cg-phase-0{animation:cg-audit 16s step-end 1 both}.cg-phase-1{animation:cg-stage 16s step-end 1 both}.cg-phase-2{animation:cg-inspect 16s step-end 1 both}.cg-phase-3{animation:cg-verify 16s step-end 1 both}.cg-source-private{animation:cg-remove 16s ease-in-out 1 both}.cg-private-files{animation:cg-store 16s ease-in-out 1 both}.cg-publish{animation:cg-publish 16s ease-in-out 1 both}.cg-probe{animation:cg-probe 16s ease-in-out 1 both}.cg-public-code{animation:cg-public-code 16s ease-in-out 1 both}
    @keyframes cg-audit{0%,24.99%{opacity:1}25%,100%{opacity:0}}@keyframes cg-stage{0%,24.99%{opacity:0}25%,49.99%{opacity:1}50%,100%{opacity:0}}@keyframes cg-inspect{0%,49.99%{opacity:0}50%,74.99%{opacity:1}75%,100%{opacity:0}}@keyframes cg-verify{0%,74.99%{opacity:0}75%,100%{opacity:1}}
    @keyframes cg-remove{0%,25%{opacity:1;transform:translateY(0)}34%,100%{opacity:0;transform:translateY(35px)}}@keyframes cg-store{0%,26%{opacity:0;transform:translateY(-20px)}35%,100%{opacity:1;transform:translateY(0)}}
    @keyframes cg-publish{0%,34%{opacity:0;transform:translate(0,0)}37%{opacity:1;transform:translate(0,0)}46%{opacity:1;transform:translate(var(--cg-publish))}49%,100%{opacity:0;transform:translate(var(--cg-publish))}}
    @keyframes cg-probe{0%,50%{opacity:0;transform:translate(0,0)}53%{opacity:1;transform:translate(0,0)}60%,64%{opacity:1;transform:translate(var(--cg-probe))}71%{opacity:1;transform:translate(0,0)}74%,100%{opacity:0;transform:translate(0,0)}}
    @keyframes cg-public-code{0%,62%{opacity:0;transform:translate(0,0)}65%{opacity:1;transform:translate(0,0)}73%{opacity:1;transform:translate(var(--cg-public))}76%,100%{opacity:0;transform:translate(var(--cg-public))}}
    .cg-demo[data-paused='true'] *{animation-play-state:paused!important}.cg-demo[data-static-stage] *{animation:none!important}.cg-demo[data-static-stage] .cg-phase{opacity:0}.cg-demo[data-static-stage='0'] .cg-phase-0,.cg-demo[data-static-stage='1'] .cg-phase-1,.cg-demo[data-static-stage='2'] .cg-phase-2,.cg-demo[data-static-stage='3'] .cg-phase-3{opacity:1}.cg-demo[data-static-stage='0'] .cg-source-private{opacity:1}.cg-demo[data-static-stage='0'] .cg-private-files{opacity:0}
    @media(prefers-reduced-motion:reduce){.cg-demo *{animation:none!important}.cg-phase{opacity:0}.cg-phase-3{opacity:1}}
  `;
  const statusX=P.x+P.w/2;
  const phaseCopy = [
    ['Audit release inputs','Private files found'],
    ['Stage the public release','Keep private files out'],
    ['REA inspects public files','Source map not shipped'],
    ['Verify the release receipt','Modification detected']
  ];
  const svg=`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" class="cg-demo" style="--cg-publish:${publishMove};--cg-probe:${probeMove};--cg-public:${publicMove}" role="img" aria-labelledby="${id}-title" aria-describedby="${id}-desc">
  <title id="${id}-title">CloneGuard and REA: reducing release exposure</title>
  <desc id="${id}-desc">Illustrative workflow. CloneGuard finds a source map and environment file, keeps them in private storage, and stages JavaScript and HTML publicly. REA can read the public files but the removed source map is not shipped. A release receipt detects a later file modification. This does not demonstrate prevention of cloning.</desc>
  <style>${css}</style>
  ${rect(0,0,W,H,'cg-bg')}
  <path class="cg-wire" d="${mobile?'M115 256 C115 295 180 295 180 326 M365 256 C365 295 306 295 306 326 M115 256 V600 M240 556 V575 H365 V600':'M308 194 H422 M698 194 H812 M698 251 H812 M168 316 V375 M560 315 V375'}"/>
  ${rect(L.x,L.y,L.w,L.h,'cg-owner')}
  ${text(L.x+18,L.y+40,'CloneGuard','cg-title')}
  ${text(L.x+18,L.y+67,'Release workflow','cg-small')}
  <path d="M${L.x+18} ${L.y+86} H${L.x+L.w-18}" class="cg-divider"/>
  ${text(L.x+18,L.y+119,'Audit, stage, verify','cg-label')}
  ${chip(L.x+18,L.y+143,mobile?162:244,mobile?'app.js + HTML':'app.js + index.html')}
  ${chip(L.x+18,L.y+189,mobile?162:244,'.map + .env','cg-source-private')}
  ${mobile?'':text(L.x+18,L.y+263,'Keep the original build.','cg-small')}
  ${rect(R.x,R.y,R.w,R.h)}
  ${text(R.x+18,R.y+40,'REA','cg-title')}
  ${text(R.x+18,R.y+67,'Analysis agent','cg-small')}
  <path d="M${R.x+18} ${R.y+86} H${R.x+R.w-18}" class="cg-divider"/>
  ${text(R.x+18,R.y+119,'Inspect public files','cg-label')}
  ${text(R.x+18,R.y+157,'Read the bundle','cg-body')}
  ${text(R.x+18,R.y+189,'Observe the UI','cg-body')}
  ${mobile?'':text(R.x+18,R.y+263,'Public behavior stays visible.','cg-small')}
  ${rect(P.x,P.y,P.w,P.h,'cg-release')}
  ${text(statusX,P.y+38,'Public release','cg-title','middle')}
  ${chip(P.x+18,P.y+61,P.w-36,'app.js')}
  ${chip(P.x+18,P.y+105,P.w-36,'index.html')}
  ${phaseCopy.map((copy,index)=>phase(index,text(statusX,P.y+180,mobile?['Inputs reviewed','Public files staged','Map not shipped','File change detected'][index]:copy[1],'cg-label','middle')+text(statusX,P.y+208,index===2?'Public code is readable.':index===3?'Receipt comparison.':'Original bytes retained.','cg-small','middle'))).join('')}
  ${rect(B.x,B.y,B.w,B.h,'cg-owner')}
  ${text(B.x+18,B.y+29,'Private storage','cg-label')}
  ${chip(B.x+18,B.y+43,B.w-36,'.map + .env','cg-private-files')}
  ${rect(V.x,V.y,V.w,V.h)}
  ${text(V.x+18,V.y+29,'Release receipt','cg-label')}
  ${phase(0,text(V.x+18,V.y+59,mobile?'Prepare inventory':'Record what will be shipped.','cg-small'))}
  ${phase(1,text(V.x+18,V.y+59,mobile?'Hash staged files':'Record hashes of the staged files.','cg-small'))}
  ${phase(2,text(V.x+18,V.y+59,mobile?'Keep the receipt':'Retain the receipt outside the public release.','cg-small'))}
  ${phase(3,text(V.x+18,V.y+59,mobile?'Changed asset':'Modified asset → receipt mismatch','cg-body'))}
  <g class="cg-packet cg-publish">${rect(publishStart.x-36,publishStart.y-15,82,30)}${text(publishStart.x+5,publishStart.y+6,'app.js','', 'middle')}</g>
  <g class="cg-packet cg-probe">${rect(probeStart.x-32,probeStart.y-15,76,30)}${text(probeStart.x+6,probeStart.y+6,'.map?','', 'middle')}</g>
  <g class="cg-packet cg-public-code">${rect(publicStart.x-36,publicStart.y-15,82,30)}${text(publicStart.x+5,publicStart.y+6,'app.js','', 'middle')}</g>
  ${phaseCopy.map((copy,index)=>phase(index,text(W/2,H-15,copy[0],'cg-label','middle'))).join('')}
</svg>\n`;
  return svg.split('\n').map(line=>line.trimEnd()).join('\n');
}
for (const mobile of [false,true]) writeFileSync(resolve(output, mobile?'cloneguard-rea-mobile.svg':'cloneguard-rea.svg'),graphic(mobile));
console.log('Wrote original desktop and mobile walkthrough SVGs.');
