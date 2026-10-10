const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const escape=s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
class Element {
 constructor(tag='div'){this.tagName=tag;this.children=[];this.style={};this.dataset={};this.listeners={};this.attributes={};this.hidden=false;this.value='';this.classList={add(){},remove(){}};this._text='';}
 set textContent(v){this._text=String(v);this.children=[];} get textContent(){return this._text+this.children.map(n=>n.textContent).join('');}
 append(...nodes){this.children.push(...nodes);nodes.forEach(n=>n.parent=this);} replaceChildren(...nodes){this._text='';this.children=[];this.append(...nodes);}
 get childElementCount(){return this.children.length;} setAttribute(k,v){this.attributes[k]=v;} addEventListener(k,v){this.listeners[k]=v;} focus(){} scrollIntoView(){} click(){this.listeners.click?.({target:this});} remove(){}
 querySelectorAll(selector){const all=[];const visit=n=>n.children.forEach(c=>{all.push(c);visit(c);});visit(this);if(selector.includes('.fw-report-nav'))return[];return all.filter(n=>n.className==='fw-detail' && (!selector.includes(':not')||!n.hidden));}
 get innerHTML(){return escape(this._text)+this.children.map(n=>`<${n.tagName}>${n.innerHTML}</${n.tagName}>`).join('');}
}
function workspace(){
 const nodes={};const get=id=>nodes[id]||=(new Element());const root=get('file-workspace');
 const document={getElementById(id){let found;const visit=n=>{if(n.id===id)found=n;n.children.forEach(visit);};Object.values(nodes).forEach(visit);return found||get(id);},createElement:tag=>new Element(tag),body:new Element('body')};
 const ctx={document,window:{addEventListener(){},print(){}},navigator:{clipboard:{writeText:async()=>{}}},setTimeout(){return 1;},clearTimeout(){},setInterval(){return 1;},clearInterval(){},AbortController,FormData:class{append(){}},Blob,URL,Date,console,fetch(){throw Error('Unexpected network');}};
 vm.createContext(ctx);let source=fs.readFileSync(path.join(__dirname,'../static/file_workspace.js'),'utf8');source=source.replace(/\}\)\(\);\s*$/,'globalThis.testAPI={render,scorePresentation,select,reset,analyze,filter};})();');vm.runInContext(source,ctx);return{ctx,nodes,get,root};
}
module.exports={workspace,Element};
