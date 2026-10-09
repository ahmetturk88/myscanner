(() => {
  'use strict';
  const workspace=document.querySelector('[data-workspace]');
  if(!workspace)return;
  const cards=[...workspace.querySelectorAll('.hx-tool')];
  const search=document.getElementById('tool-search');
  let category='All';
  function filterTools(){
    const query=search.value.trim().toLowerCase();
    let visible=0;
    for(const card of cards){
      const matches=(category==='All'||card.dataset.category===category)&&card.dataset.search.includes(query);
      card.hidden=!matches;if(matches)visible++;
    }
    document.getElementById('tool-empty').hidden=visible!==0;
  }
  search.addEventListener('input',filterTools);
  workspace.querySelectorAll('[data-filter]').forEach(button=>button.addEventListener('click',()=>{
    category=button.dataset.filter;
    workspace.querySelectorAll('[data-filter]').forEach(other=>other.setAttribute('aria-pressed',String(other===button)));
    filterTools();
  }));
  document.getElementById('sample-url').addEventListener('click',()=>{
    const input=document.getElementById('url-input');input.value='https://example.com/';input.focus();
  });
  document.getElementById('home-scan-form').addEventListener('submit',event=>{
    const form=event.currentTarget;
    if(form.dataset.submitted==='1'){event.preventDefault();return;}
    form.dataset.submitted='1';
    form.querySelector('button[type=submit]').disabled=true;
    document.getElementById('scan-submit-state').textContent='Submitting your request. Analysis starts after the server queues it.';
  });
  window.addEventListener('pageshow',()=>{
    const form=document.getElementById('home-scan-form');delete form.dataset.submitted;
    form.querySelector('button[type=submit]').disabled=false;
    document.getElementById('scan-submit-state').textContent='';
  });
  const status=document.getElementById('recent-status');
  const list=document.getElementById('recent-list');
  const refresh=document.getElementById('refresh-reports');
  function node(tag,className,text){const element=document.createElement(tag);element.className=className; if(text!==undefined)element.textContent=text;return element;}
  const labels={malicious:['Threat reported','threat'],high_risk:['High risk','threat'],suspicious:['Needs review','review'],unknown:['Needs verification','review'],pending:['Pending','review'],harmless:['No threat indicated','neutral']};
  async function loadReports(){
    refresh.disabled=true;status.textContent='Loading saved reports…';
    const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),10000);
    try{
      const response=await fetch(workspace.dataset.recentUrl,{credentials:'same-origin',headers:{Accept:'application/json'},signal:controller.signal});
      if(!response.ok)throw Error('Unavailable');
      const data=await response.json();if(!Array.isArray(data.scans))throw Error('Invalid response');
      const scans=data.scans.slice(0,15).filter(scan=>scan&&Number.isSafeInteger(scan.id)&&scan.id>0&&typeof scan.url==='string');
      list.replaceChildren();
      document.getElementById('recent-count').textContent=String(scans.length);
      document.getElementById('recent-threats').textContent=String(scans.filter(scan=>['malicious','high_risk'].includes(scan.verdict)).length);
      document.getElementById('recent-review').textContent=String(scans.filter(scan=>!['harmless','malicious','high_risk'].includes(scan.verdict)).length);
      for(const scan of scans){
        const link=node('a','hx-report');
        link.href=workspace.dataset.reportBase.replace(/\/0$/, '/'+scan.id);
        const icon=node('span','hx-report-icon','↗');icon.setAttribute('aria-hidden','true');
        const target=node('div','hx-report-target');
        target.append(node('strong','',scan.url),node('small','',typeof scan.date==='string'?scan.date:'Date unavailable'));
        const [label,tone]=labels[scan.verdict]||['Needs verification','review'];
        const verdict=node('span','hx-verdict',label);verdict.dataset.tone=tone;
        link.append(icon,target,verdict);list.append(link);
      }
      status.textContent=scans.length?'Latest saved reports. Open a report for its findings and coverage.':'No saved reports yet. Start with a URL above.';
    }catch(error){
      list.replaceChildren();
      for(const id of ['recent-count','recent-threats','recent-review'])document.getElementById(id).textContent='—';
      status.textContent='Reports could not be loaded. Refresh to try again, or check your sign-in session.';
    }finally{clearTimeout(timeout);refresh.disabled=false;}
  }
  refresh.addEventListener('click',loadReports);
  loadReports();
})();
