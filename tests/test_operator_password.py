import asyncio
import base64
import json
from pathlib import Path
import shutil
import subprocess
import threading
import unittest
from unittest.mock import patch

import httpx
import test_platform as fixtures
from local_observe.platform.api import create_app
from local_observe.platform import operator, operator_account as accounts


class PasswordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = '  p\u00e4ss:\U0001f511  '
        cls.account = accounts.make_account('alice',cls.password)
        cls.human = 'internal-human-test-token-'*3
        cls.reader = 'machine-reader-test-token-'*3

    def setUp(self):
        self.fixture = fixtures.PlatformTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.api = create_app(self.fixture.store,[
            {'identity':'operator','role':'human','token':self.human},
            {'identity':'reader','role':'reader','token':self.reader}],self.fixture.policy,index_path=self.fixture.index)

    def basic(self,password=None):
        return 'Basic '+base64.b64encode(('alice:'+(self.password if password is None else password)).encode()).decode()

    def test_actual_api_password_identity_machine_bearer_and_redaction(self):
        async def check():
            app = operator.with_ui(self.api,self.account,self.human)
            with self.assertLogs('httpx',level='INFO') as logs:
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://localhost') as client:
                    metadata = await client.get('/v1/operator-auth')
                    self.assertEqual(metadata.json(),{'mode':'password'})
                    self.assertEqual(metadata.headers['cache-control'],'no-store')
                    result = await client.get('/v1/me',headers={'Authorization':self.basic()})
                    self.assertEqual(result.status_code,200)
                    self.assertEqual(result.json(),{'identity':'operator','role':'human'})
                    for header in [self.basic('wrong'),'Basic !!!','Basic '+base64.b64encode(b'alice:\xff').decode()]:
                        denied = await client.get('/v1/me',headers={'Authorization':header})
                        self.assertEqual(denied.status_code,401)
                        self.assertEqual(denied.json(),{'error':'authentication_required'})
                    duplicate = await client.get('/v1/me',headers=[('Authorization',self.basic()),('Authorization','Bearer '+self.reader)])
                    self.assertEqual(duplicate.status_code,401)
                    machine = await client.get('/v1/me',headers={'Authorization':'Bearer '+self.reader})
                    self.assertEqual(machine.json(),{'identity':'reader','role':'reader'})
                    self.assertNotIn('set-cookie',result.headers)
                    self.assertNotIn('www-authenticate',denied.headers)
            emitted = json.dumps([result.json(),metadata.json(),logs.output])
            for secret in [self.password,self.human,self.reader,self.account['password_hash'],self.basic()]:
                self.assertNotIn(secret,emitted)
        asyncio.run(check())

    def test_legacy_metadata_and_password_disabled(self):
        async def check():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=operator.with_ui(self.api)),base_url='http://localhost') as client:
                self.assertEqual((await client.get('/v1/operator-auth')).json(),{'mode':'token'})
                self.assertEqual((await client.get('/v1/me',headers={'Authorization':self.basic()})).status_code,401)
                self.assertEqual((await client.get('/v1/me',headers={'Authorization':'Bearer '+self.human})).status_code,200)
        asyncio.run(check())

    def test_cancelled_requests_keep_kdf_slots_until_threads_finish(self):
        async def check():
            release = threading.Event()
            entered = 0
            lock = threading.Lock()
            def slow(*args):
                nonlocal entered
                with lock: entered += 1
                release.wait(5)
                return True
            app = operator.with_ui(self.api,self.account,self.human)
            with patch.object(accounts,'verify_password',side_effect=slow):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://localhost') as client:
                    tasks = [asyncio.create_task(client.get('/v1/me',headers={'Authorization':self.basic()})) for _ in range(2)]
                    try:
                        for _ in range(100):
                            if entered == 2: break
                            await asyncio.sleep(.01)
                        self.assertEqual(entered,2)
                        # The loop and machine authentication remain responsive while KDFs block.
                        self.assertEqual((await client.get('/v1/me',headers={'Authorization':'Bearer '+self.reader})).status_code,200)
                        for task in tasks: task.cancel()
                        await asyncio.gather(*tasks,return_exceptions=True)
                        busy = await client.get('/v1/me',headers={'Authorization':self.basic()})
                        self.assertEqual(busy.status_code,503)
                        self.assertEqual(entered,2)
                    finally:
                        release.set()
                        await asyncio.gather(*tasks,return_exceptions=True)
                        await asyncio.sleep(.05)
                    self.assertEqual((await client.get('/v1/me',headers={'Authorization':self.basic()})).status_code,200)
        asyncio.run(check())

    def test_startup_identity_and_malformed_file_fail_closed(self):
        with patch('local_observe.platform.api.app_factory',return_value=self.api) as platform, patch('local_observe.platform.api.role_credentials',return_value=[{'identity':'wrong','role':'human','token':self.human}]), patch.object(operator,'operator_account_from_environment',return_value=self.account):
            with self.assertRaisesRegex(ValueError,'identity'): operator.app_factory()
            platform.assert_not_called()
        with patch('local_observe.platform.api.app_factory',return_value=self.api) as platform, patch.object(operator,'operator_account_from_environment',side_effect=ValueError(accounts.MALFORMED_ACCOUNT)):
            with self.assertRaises(ValueError): operator.app_factory()
            platform.assert_not_called()

    def test_verifier_failure_returns_fixed_response_without_exception_details(self):
        async def check():
            app = operator.with_ui(self.api,self.account,self.human)
            with patch.object(accounts,'verify_password',side_effect=RuntimeError('sensitive verifier detail')):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://localhost') as client:
                    response = await client.get('/v1/me',headers={'Authorization':self.basic()})
                    self.assertEqual(response.status_code,503)
                    self.assertEqual(response.json(),{'error':'operator_login_busy'})
                    self.assertNotIn('sensitive',response.text)
        asyncio.run(check())

    @unittest.skipUnless(shutil.which('node'),'Node required for actual UI execution')
    def test_ui_password_and_legacy_login_and_logout_in_memory(self):
        static = Path(operator.__file__).parent/'static'
        source = (static/'ui.js').read_text(encoding='utf-8')
        for forbidden in ['localStorage','sessionStorage','document.cookie','indexedDB']:
            self.assertNotIn(forbidden,source)
        javascript = r'''
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const dir = process.argv[1], html = fs.readFileSync(dir+'/index.html','utf8');
const source = fs.readFileSync(dir+'/ui.js','utf8');
async function check(mode) {
 const ids = new Map(), calls = [];
 const element = () => ({value:'',dataset:{},hidden:false,disabled:false,open:false,textContent:'',
   append(){},replaceChildren(){},setAttribute(){},addEventListener(){},
   close(){this.open=false;},showModal(){this.open=true;},classList:{toggle(){},add(){},remove(){}}});
 for (const m of html.matchAll(/id="([^"]+)"/g)) ids.set(m[1],element());
 const context = vm.createContext({TextEncoder,console,
   document:{getElementById(id){assert.ok(ids.has(id),id);return ids.get(id);},createElement:element,querySelectorAll:()=>[]},
   lucide:{createIcons(){}},btoa:s=>Buffer.from(s,'binary').toString('base64'),
   fetch:async(path,options={})=>{calls.push([path,options]);return {ok:true,status:200,json:async()=>
     path==='/v1/operator-auth'?{mode}:path==='/v1/me'?{identity:'operator',role:'human'}:
     path==='/v1/status'?{incidents:{},actions:{},notifications:{}}:path==='/v1/runtime'?{notification_mode:'off'}:{rows:[]}};}
 });
 vm.runInContext(source,context);
 await new Promise(r=>setImmediate(r));
 assert.equal(ids.get('password-field').hidden,mode!=='password');
 assert.equal(ids.get('token-field').hidden,mode!=='token');
 ids.get('username').value='alice';ids.get('password').value='  päss:🔑  ';ids.get('token').value='legacy-only';
 await ids.get('login-form').onsubmit({preventDefault(){}});
 const expected = mode==='password'?'Basic '+Buffer.from('alice:  päss:🔑  ').toString('base64'):'Bearer legacy-only';
 assert.equal(calls.find(([p])=>p==='/v1/me')[1].headers.Authorization,expected);
 assert.equal(ids.get('identity').textContent,'operator / human');
 for(const name of ['username','password','token'])assert.equal(ids.get(name).value,'');
 await vm.runInContext("historyFetch('/v1/history')",context);
 assert.equal(calls.at(-1)[1].headers.Authorization,expected);
 ids.get('logout').onclick();
 assert.equal(vm.runInContext('token',context),'');
 assert.equal(ids.get('identity').textContent,'Disconnected');
 assert.equal(ids.get('login').open,true);
}
(async()=>{await check('password');await check('token');})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        result = subprocess.run(['node','-e',javascript,str(static)],capture_output=True,text=True,encoding='utf-8')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
