(function(){'use strict';
const dialog=document.getElementById('platform-tools');if(!dialog)return;
const triggers=Array.from(document.querySelectorAll('[data-shell-open]')),search=document.getElementById('shell-search'),tools=Array.from(dialog.querySelectorAll('[data-shell-tool]')),filters=Array.from(dialog.querySelectorAll('[data-shell-category]')),count=document.getElementById('shell-search-count');
let category='all',opener=null,previousOverflow='';
function filter(){const query=search.value.trim().toLocaleLowerCase();let visible=0;tools.forEach(t=>{const match=(category==='all'||t.dataset.category===category)&&t.textContent.toLocaleLowerCase().includes(query);t.hidden=!match;if(match)visible++;});count.textContent=visible?visible+' tools match your selection':'No matching tools. Try another category or search.';}
function open(trigger){if(dialog.open)return;opener=trigger;previousOverflow=document.body.style.overflow;dialog.showModal();document.body.style.overflow='hidden';triggers.forEach(t=>t.setAttribute('aria-expanded','true'));search.focus();}
function close(){dialog.close();}
dialog.addEventListener('close',()=>{document.body.style.overflow=previousOverflow;triggers.forEach(t=>t.setAttribute('aria-expanded','false'));opener?.focus();});
triggers.forEach(t=>t.addEventListener('click',()=>open(t)));document.getElementById('shell-close').addEventListener('click',close);
dialog.addEventListener('click',e=>{if(e.target===dialog){const r=dialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)close();}});
search.addEventListener('input',filter);filters.forEach(b=>b.addEventListener('click',()=>{category=b.dataset.shellCategory;filters.forEach(x=>x.setAttribute('aria-pressed',String(x===b)));filter();}));
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();if(dialog.open)search.focus();else open(triggers.find(t=>t.offsetParent!==null)||triggers[0]);}});
const header=document.getElementById('platform-header'),progress=document.getElementById('shell-reading');let queued=false;
function update(){queued=false;const y=window.scrollY||0;header.classList.toggle('is-scrolled',y>12);const height=document.documentElement.scrollHeight-window.innerHeight;progress.style.transform='scaleX('+(height>0?Math.max(0,Math.min(1,y/height)):0)+')';}
window.addEventListener('scroll',()=>{if(!queued){queued=true;requestAnimationFrame(update);}},{passive:true});window.addEventListener('resize',update);update();
document.getElementById('shell-year').textContent=String(new Date().getFullYear());
document.querySelectorAll('.shell-menu').forEach(menu=>{document.addEventListener('click',e=>{if(menu.open&&!menu.contains(e.target))menu.open=false;});document.addEventListener('keydown',e=>{if(e.key==='Escape'&&menu.open){menu.open=false;menu.querySelector('summary').focus();}});});
document.getElementById('shell-top').addEventListener('click',()=>{window.scrollTo({top:0,behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'});document.querySelector('.shell-brand').focus({preventScroll:true});});
})();
