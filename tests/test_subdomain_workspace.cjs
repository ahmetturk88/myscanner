const assert=require('node:assert/strict');
const fs=require('node:fs');
const {selectRows,csvCell,brief}=require('../static/subdomain_workspace.js');
const data={domain:'example.com',results:[
 {full_domain:'b.example.com',addresses:['8.8.8.8'],sources:['common_name'],verdict:'active',possible_wildcard:true,tls:{status:'invalid'}},
 {full_domain:'a.example.com',addresses:['1.1.1.1'],sources:['certificate_transparency'],verdict:'dns_only',possible_wildcard:false,tls:{status:'not_requested'}}]};
assert.equal(selectRows(data)[0].full_domain,'a.example.com');
assert.equal(selectRows(data,'8.8.8.8').length,1);
assert.equal(selectRows(data,'','wildcard')[0].full_domain,'b.example.com');
assert.equal(selectRows(data,'','all','certificate_transparency').length,1);
assert.equal(selectRows(data,'','all','all','invalid')[0].full_domain,'b.example.com');
assert.equal(selectRows(data,'missing').length,0);
for(const attack of ['=cmd',' +cmd','-cmd','@cmd','\tcmd'])assert.ok(csvCell(attack).startsWith('"\''));
assert.equal(csvCell('a"b'),'"a""b"');
assert.equal(brief({...data,total_found:2,candidates_selected:80,active_count:1,redirect_count:0,dns_error_count:1,wildcard:{detected:null}}).length,5);
assert.ok(brief({...data,wildcard:{detected:null}})[2].includes('incomplete'));
const source=fs.readFileSync(require.resolve('../static/subdomain_workspace.js'),'utf8');
assert.ok(!source.includes('innerHTML'));assert.ok(!source.includes('insertAdjacentHTML'));
console.log('PASS: combined filters, sorting, unknown wildcard narrative, CSV formula escaping and text-only renderer');
