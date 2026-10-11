import assert from 'node:assert/strict';
import test from 'node:test';
import { request } from '../src/utils.ts';
test('request reports non-JSON access errors and refuses HTTP errors claiming success', async () => {
  const previousFetch=globalThis.fetch;
  try {
    globalThis.fetch=async()=>new Response('access denied',{status:403});
    const denied=await request('/api/settings',undefined,{silent:true});
    assert.equal(denied.success,false);assert.match(denied.msg,/IP\/CIDR/);
    globalThis.fetch=async()=>new Response(JSON.stringify({success:true,obj:{value:'wrong'}}),{status:500});
    assert.equal((await request('/api/settings',undefined,{silent:true})).success,false);
    for (const value of ['null','[]','{}','<html>bad gateway</html>']) {
      globalThis.fetch=async()=>new Response(value,{status:200});
      assert.equal((await request('/api/settings',undefined,{silent:true})).success,false);
    }
  } finally { globalThis.fetch=previousFetch; }
});
