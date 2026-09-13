const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {EventEmitter} = require('node:events');
let callback;
const requests=[];
const fakeHttp={request(options,onResponse){
 const request=new EventEmitter();
 request.end=body=>{
  requests.push({options,body:JSON.parse(body)});
  const response=new EventEmitter();response.statusCode=202;response.resume=()=>{};
  onResponse(response);response.emit('end');
 };
 return request;
}};
const context={module:{exports:{}},Buffer,console:{log(){},error(){}},setTimeout,require(name){
 if(name==='fs')return {readFileSync(){return JSON.stringify({groupKey:'arena',token:'x'.repeat(40),port:8766});}};
 if(name==='http')return fakeHttp;
 throw Error('unexpected module');
}};
vm.runInNewContext(fs.readFileSync(__dirname+'/../shinobi_upload_hook.js','utf8'),context);
const s={insertCompletedVideoExtender(cb){callback=cb;}};
context.module.exports(s);
assert.equal(requests.length,0);
callback({ke:'other',mid:'camera02'},{filename:'clip.mp4'});assert.equal(requests.length,0);
callback({ke:'arena',mid:'camera02'},{filename:'clip.mp4'});
assert.equal(requests.length,1);assert.equal(requests[0].body.filename,'clip.mp4');
assert.equal(requests[0].options.host,'127.0.0.1');
assert.equal(requests[0].options.path,'/video-complete');
assert.equal(requests[0].options.headers.Authorization,'Bearer '+'x'.repeat(40));
console.log('completion hook tests passed');
