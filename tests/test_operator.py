import asyncio
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

import httpx

import test_platform as fixtures
from local_observe.platform.api import create_app
from local_observe.platform.operator import with_ui


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.PlatformTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_terminal_execution_retry_requires_same_runner_and_outcome(self):
        from local_observe.platform.state import Actor, StateError
        fixture = self.fixture
        claim = fixture.store.claim_action(fixture.approved(), fixtures.RUNNER, fixture.policy, now=fixtures.NOW)
        args = (claim['execution_id'], 'succeeded', fixtures.RUNNER, claim['runner_token'])
        self.assertEqual(fixture.store.execution_outcome(*args, now=fixtures.NOW), {'status': 'succeeded'})
        before = len(fixture.store.records('audit'))
        self.assertEqual(fixture.store.execution_outcome(*args, now=fixtures.NOW), {'status': 'succeeded'})
        self.assertEqual(before, len(fixture.store.records('audit')))
        with self.assertRaises(StateError):
            fixture.store.execution_outcome(claim['execution_id'], 'failed', fixtures.RUNNER, claim['runner_token'], now=fixtures.NOW)
        with self.assertRaises(StateError):
            fixture.store.execution_outcome(claim['execution_id'], 'succeeded', Actor('other-runner', 'executor'), claim['runner_token'], now=fixtures.NOW)

    def test_operator_assets_and_role_enforcement(self):
        action_id = self.fixture.action()[0]['action_id']
        async def check():
            app = with_ui(create_app(self.fixture.store, [
                {'identity': 'operator', 'role': 'human', 'token': 'human-test-token-' * 3},
                {'identity': 'reader', 'role': 'reader', 'token': 'reader-test-token-' * 3}], self.fixture.policy, index_path=self.fixture.index))
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost') as client:
                response = await client.get('/')
                self.assertEqual(response.status_code, 200)
                self.assertIn('frame-ancestors', response.headers['content-security-policy'])
                self.assertEqual((await client.get('/v1/status')).status_code, 401)
                reader = {'Authorization': 'Bearer ' + 'reader-test-token-' * 3}
                self.assertEqual((await client.get('/v1/me', headers=reader)).json()['role'], 'reader')
                self.assertEqual(len((await client.get('/v1/inventory', headers=reader)).json()['rows']), 2)
                action = (await client.get('/v1/records/actions', headers=reader)).json()['rows'][0]
                self.assertNotIn(action_id, action['display']['description'])
                self.assertEqual(action['display']['host_name'], 'probe-1')
                self.assertEqual(action['display']['resource_name'], 'probe-1')
                self.assertEqual((await client.post('/v1/actions/decision', headers=reader, json={'action_id': action_id, 'decision': 'approved'})).status_code, 400)
                self.assertEqual((await client.get('/v1/records/events?limit=100000', headers=reader)).status_code, 400)
        asyncio.run(check())

    @unittest.skipUnless(importlib.util.find_spec('playwright') and os.environ.get('LO_TEST_BROWSER'),
                         'browser check requires Playwright and LO_TEST_BROWSER executable')
    def test_action_approval_in_chromium_with_real_platform_api(self):
        """Browser requests are fulfilled through ASGI; no listening socket or external traffic."""
        from playwright.async_api import async_playwright, expect
        from local_observe.platform.runner_handoff import RunnerHandoff
        from test_action_invariants import reviewed_binding
        from test_platform_tools import HOST, HUMAN_TOKEN, Platform
        from test_runner_handoff import RUNNER_TOKEN

        async def check():
            async with async_playwright() as browser_api:
                browser = await browser_api.chromium.launch(executable_path=os.environ['LO_TEST_BROWSER'])
                try:
                    for width, height in ((1440, 960), (390, 844)):
                        platform = Platform()
                        self.addCleanup(platform.close)
                        platform.store.path.chmod(0o600)
                        binding = reviewed_binding([HOST])
                        binding['dag'] += '-' + binding['sha256'][:16]
                        platform.app = create_app(platform.store, [
                            {'identity': 'agent-ask', 'role': 'proposer', 'token': platform.tokens['proposer']},
                            {'identity': 'operator', 'role': 'human', 'token': HUMAN_TOKEN},
                            {'identity': 'trusted-runner', 'role': 'executor', 'token': RUNNER_TOKEN}],
                            platform.policy, index_path=platform.index_path,
                            runner_handoff=RunnerHandoff(platform.store, platform.policy,
                                                         {'trusted-runner': [binding]}))
                        proposal = await asyncio.to_thread(platform.proposal, retry_key=platform.next_key())
                        action = proposal['action_id']
                        app = with_ui(platform.app)
                        decisions, errors = [], []
                        fault = {'review': 0, 'decision': 0}
                        context = await browser.new_context(viewport={'width': width, 'height': height})
                        page = await context.new_page()
                        page.on('pageerror', lambda error: errors.append(str(error)))
                        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                                     base_url='https://operator.example.test') as client:
                            async def route_request(route):
                                request = route.request
                                url = httpx.URL(request.url)
                                if url.host != 'operator.example.test':
                                    await route.abort()
                                    raise AssertionError('Unexpected browser origin')
                                if url.path == '/v1/actions/decision':
                                    decisions.append(request.post_data_json)
                                    if fault['decision']:
                                        await route.fulfill(status=fault['decision'], json={'error': 'refused'})
                                        return
                                if url.path == '/v1/actions/review' and fault['review']:
                                    await route.fulfill(status=fault['review'], json={'error': 'refused'})
                                    return
                                response = await client.request(request.method, request.url,
                                                                headers=request.headers, content=request.post_data)
                                await route.fulfill(status=response.status_code, headers=dict(response.headers),
                                                    body=response.content)

                            await context.route('**/*', route_request)
                            await page.goto('https://operator.example.test/')
                            await page.locator('#token').fill(HUMAN_TOKEN)
                            await page.get_by_role('button', name='Sign in', exact=True).click()
                            await expect(page.locator('#login')).not_to_be_visible()
                            await page.locator('[data-view="actions"]').click()
                            await page.get_by_role('button', name='Inspect record').click()
                            await page.get_by_role('button', name='Approve', exact=True).click()
                            confirm = page.locator('#confirm')
                            await expect(confirm).to_be_visible()
                            review = (await client.get('/v1/actions/review?action_id=' + action,
                                                       headers={'Authorization': 'Bearer ' + HUMAN_TOKEN})).json()
                            displayed = await page.locator('#confirm-subject dd').all_text_contents()
                            for expected in (action, 'inspect', '1', HOST, binding['dag'], binding['sha256'],
                                             review['binding_sha256'], review['request_sha256'], 'trusted-runner'):
                                self.assertIn(expected, displayed)
                            self.assertFalse(decisions)
                            self.assertTrue(await confirm.evaluate('(el) => el.scrollWidth <= el.clientWidth'))
                            await page.keyboard.press('Escape')
                            await expect(confirm).not_to_be_visible()
                            self.assertFalse(decisions)

                            fault['review'] = 503
                            await page.get_by_role('button', name='Approve', exact=True).click()
                            await expect(page.locator('#detail-error')).to_contain_text('No decision was sent')
                            await expect(confirm).not_to_be_visible()
                            self.assertFalse(decisions)
                            fault['review'] = 0
                            fault['decision'] = 400
                            await page.get_by_role('button', name='Approve', exact=True).click()
                            await confirm.get_by_role('button', name='Confirm', exact=True).click()
                            await expect(page.locator('#detail-error')).to_contain_text('Request refused (400)')
                            await expect(page.locator('#detail')).to_be_visible()
                            self.assertEqual(decisions[-1], {'action_id': action, 'decision': 'approved',
                                                            'binding_sha256': review['binding_sha256']})

                            fault['decision'] = 0
                            await page.get_by_role('button', name='Approve', exact=True).click()
                            await confirm.get_by_role('button', name='Confirm', exact=True).click()
                            await expect(page.locator('#detail')).not_to_be_visible()
                            await expect(page.locator('#records')).to_contain_text('approved')
                            await page.get_by_role('button', name='Inspect record').click()
                            await page.get_by_role('button', name='Withdraw approval', exact=True).click()
                            await confirm.get_by_role('button', name='Confirm', exact=True).click()
                            await expect(page.locator('#records')).to_contain_text('denied')
                            self.assertEqual(decisions[-1], {'action_id': action, 'decision': 'denied'})
                            proposal = await asyncio.to_thread(platform.proposal, retry_key=platform.next_key())
                            await page.get_by_role('button', name='Refresh', exact=True).click()
                            pending = page.locator('#records tr').filter(has_text='pending')
                            await pending.get_by_role('button', name='Inspect record').click()
                            await page.get_by_role('button', name='Deny', exact=True).click()
                            await confirm.get_by_role('button', name='Confirm', exact=True).click()
                            await expect(pending).to_have_count(0)
                            self.assertEqual(decisions[-1], {'action_id': proposal['action_id'], 'decision': 'denied'})
                            self.assertEqual(platform.executions(), [])
                            self.assertFalse(errors)
                        await context.close()
                finally:
                    await browser.close()
        asyncio.run(check())

    @unittest.skipUnless(shutil.which('node'), 'Node required for actual UI execution')
    def test_action_ui_reviews_exact_binding_denies_withdraws_and_rejects_stale_confirmation(self):
        static = Path(__file__).parents[1] / 'local_observe/platform/static'
        javascript = r'''
const fs = require('fs'), vm = require('vm'), assert = require('assert/strict');
const root = process.argv[1], source = fs.readFileSync(root+'/ui.js','utf8');
const html = fs.readFileSync(root+'/index.html','utf8');
const action = '11111111-1111-4111-8111-111111111111';
const target = '22222222-2222-4222-8222-222222222222';
const request = {action:'inspect',version:'1',targets:[target],parameters:{},evidence:[],
  expires_at:'2099-01-01T00:00:00Z'};
const row = {id:action,status:'pending',payload:JSON.stringify(request),
  display:{description:'<img src=x onerror=alert(1)>'}};
const expected = {action_id:action,request,request_sha256:'a'.repeat(64),runner:'trusted-runner',
  binding:{action:'inspect',version:'1',targets:[target],dag:'inspect-versioned',sha256:'b'.repeat(64)},
  binding_sha256:'c'.repeat(64)};
function element(tag='div') {
 const events = new Map();
 return {tag,children:[],_text:'',value:'',dataset:{},hidden:false,disabled:false,open:false,
   get textContent(){return this._text+this.children.map(c=>c.textContent||'').join(' ');},
   set textContent(value){this._text=String(value);this.children=[];},
   set innerHTML(value){throw new Error('HTML injection sink used');},
   append(...children){this.children.push(...children);},
   replaceChildren(...children){this._text='';this.children=children;},
   setAttribute(name,value){this[name]=value;},
   addEventListener(name,callback,options={}){if(!events.has(name))events.set(name,[]);
     events.get(name).push({callback,once:options.once});},
   close(answer){if(answer!==undefined)this.returnValue=answer;this.open=false;
     const list=events.get('close')||[];events.set('close',list.filter(e=>!e.once));
     for(const e of list)e.callback();},
   showModal(){this.open=true;},classList:{toggle(){},add(){},remove(){}}};
}
const tick = ()=>new Promise(resolve=>setImmediate(resolve));
async function fixture({review=expected,reviewStatus=200,decisionStatus=200,defer=false}={}) {
 const ids=new Map(),calls=[];let finish;
 for(const match of html.matchAll(/id="([^"]+)"/g))ids.set(match[1],element());
 const reply=(body,status=200)=>({ok:status===200,status,json:async()=>JSON.parse(JSON.stringify(body))});
 const context=vm.createContext({console,TextEncoder,URLSearchParams,
   document:{getElementById:id=>ids.get(id),createElement:element,createTextNode:text=>({textContent:text}),
     querySelectorAll:()=>[]},lucide:{createIcons(){}},
   fetch:async(route,options={})=>{calls.push([route,options]);
     if(route.startsWith('/v1/actions/review')){
       if(defer)return new Promise(resolve=>{finish=()=>resolve(reply(review,reviewStatus));});
       return reply(review,reviewStatus);
     }
     if(route==='/v1/actions/decision')return reply({status:'approved'},decisionStatus);
     if(route==='/v1/operator-auth')return reply({mode:'token'});
     if(route==='/v1/status')return reply({incidents:{},actions:{},notifications:{}});
     return reply({rows:[]});
   }});
 vm.runInContext(source,context);await tick();context.row=JSON.parse(JSON.stringify(row));
 vm.runInContext("token='synthetic-human-session';role='human';view='actions';details(row)",context);
 return {ids,calls,context,finish:()=>finish(),buttons:()=>ids.get('commands').children,
   posts:()=>calls.filter(([p])=>p==='/v1/actions/decision')};
}
async function run() {
 let checks=0;
 {
  const f=await fixture(),button=f.buttons().find(b=>b.title==='Approve');
  const pending=button.onclick();await tick();
  await f.buttons().find(b=>b.title==='Deny').onclick();
  assert.equal(f.posts().length,0);assert.equal(f.ids.get('confirm').open,true);
  assert.equal(f.ids.get('confirm-title').textContent,'Approve');
  const text=f.ids.get('confirm-subject').textContent;
  for(const value of [action,target,'inspect','1','inspect-versioned','trusted-runner',
                     expected.binding.sha256,expected.binding_sha256,expected.request_sha256])
    assert.ok(text.includes(value),value);
  f.ids.get('confirm').close('confirm');await pending;
  assert.deepEqual(JSON.parse(f.posts()[0][1].body),
    {action_id:action,decision:'approved',binding_sha256:expected.binding_sha256});checks++;
 }
 {
  const f=await fixture(),pending=f.buttons().find(b=>b.title==='Approve').onclick();await tick();
  f.ids.get('confirm').close('cancel');await pending;assert.equal(f.posts().length,0);checks++;
 }
 for(const status of [400,403,404,500,503]) {
  const f=await fixture({reviewStatus:status});await f.buttons()[0].onclick();
  assert.equal(f.posts().length,0);assert.equal(f.ids.get('confirm').open,false);
  assert.match(f.ids.get('detail-error').textContent,/No decision was sent/);checks++;
 }
 for(const review of [{...expected,action_id:target},{...expected,binding_sha256:'bad'},
      {...expected,binding:{...expected.binding,targets:[action]}},
      {...expected,binding:{...expected.binding,dag:'<img src=x onerror=alert(1)>'}},
      {...expected,runner_token:'synthetic-runner-capability'}]) {
  const f=await fixture({review});await f.buttons()[0].onclick();assert.equal(f.posts().length,0);
  assert.equal(f.ids.get('confirm').open,false);assert.ok(!f.ids.get('detail-error').textContent.includes('capability'));
  checks++;
 }
 {
  const f=await fixture({decisionStatus:400}),pending=f.buttons()[0].onclick();await tick();
  f.ids.get('confirm').close('confirm');await pending;
  assert.equal(f.posts().length,1);assert.match(f.ids.get('detail-error').textContent,/400/);
  assert.equal(f.ids.get('detail').open,true);assert.equal(f.buttons()[0].disabled,false);checks++;
 }
 for(const status of ['pending','approved']) {
  const f=await fixture();f.context.row.status=status;vm.runInContext('details(row)',f.context);
  const label=status==='pending'?'Deny':'Withdraw approval';
  const pending=f.buttons().find(b=>b.title===label).onclick();await tick();
  f.ids.get('confirm').close('confirm');await pending;
  assert.deepEqual(JSON.parse(f.posts()[0][1].body),{action_id:action,decision:'denied'});
  assert.equal(f.calls.filter(([p])=>p.startsWith('/v1/actions/review')).length,0);checks++;
 }
 for(const status of ['executing','denied','expired','succeeded','unknown']) {
  const f=await fixture();f.context.row.status=status;vm.runInContext('details(row)',f.context);
  assert.equal(f.buttons().length,0);checks++;
 }
 {
  const f=await fixture();vm.runInContext("role='reader';details(row)",f.context);
  assert.equal(f.buttons().length,0);checks++;
 }
 for(const afterReview of [false,true]) {
  const f=await fixture({defer:!afterReview}),pending=f.buttons()[0].onclick();await tick();
  vm.runInContext('signout()',f.context);if(!afterReview)f.finish();await pending;
  assert.equal(f.posts().length,0);assert.equal(f.ids.get('confirm').open,false);checks++;
 }
 {
  const f=await fixture({defer:true}),pending=f.buttons()[0].onclick();await tick();
  f.context.row={...row,id:target};vm.runInContext('details(row)',f.context);f.finish();await pending;
  assert.equal(f.posts().length,0);assert.equal(f.ids.get('confirm').open,false);checks++;
 }
 console.log(JSON.stringify({checks}));
}
run().catch(error=>{console.error(error);process.exitCode=1;});
'''
        result = subprocess.run(['node', '-e', javascript, str(static)], capture_output=True,
                                text=True, encoding='utf-8', timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['checks'], 24)

    def test_environment_badge_reports_the_serving_delivery_mode(self):
        """The shell ships no fixed environment label; the badge reads the runtime observation."""
        async def check():
            app = with_ui(create_app(self.fixture.store, [
                {'identity': 'operator', 'role': 'human', 'token': 'human-test-token-' * 3}], self.fixture.policy, index_path=self.fixture.index))
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost') as client:
                page = await client.get('/')
                self.assertNotIn('STAGING', page.text)
                self.assertIn('id="environment">UNKNOWN<', page.text)
                # script-src 'self' is only satisfiable while the shell carries no inline script.
                self.assertNotIn('<script>', page.text)
                self.assertIn('/v1/runtime', (await client.get('/ui.js')).text)
                human = {'Authorization': 'Bearer ' + 'human-test-token-' * 3}
                mode = (await client.get('/v1/runtime', headers=human)).json()['notification_mode']
                self.assertEqual(mode, self.fixture.store.notification_policy.delivery_mode)
                self.assertIn(mode, ('off', 'recording', 'live'))
                self.assertEqual((await client.get('/v1/runtime')).status_code, 401)
        asyncio.run(check())


@unittest.skipUnless(importlib.util.find_spec('mcp'), 'Optional MCP extra not installed; run the MCP test tier separately')
class MCPTests(unittest.TestCase):
    def test_authenticated_protocol_and_read_only_tools(self):
        from local_observe.platform.mcp import create_server
        class Client:
            def request(self, method, path):
                if method != 'GET':
                    raise AssertionError('MCP attempted a mutation')
                return 200, {'schema_version': 1}
        async def check():
            app, server = create_server(Client(), 'mcp-read-only-test-token-' * 2)
            async with server.session_manager.run():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost:8000') as client:
                    body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}
                    self.assertEqual((await client.post('/mcp', json=body)).status_code, 401)
                    headers = {'Authorization': 'Bearer ' + 'mcp-read-only-test-token-' * 2, 'Accept': 'application/json, text/event-stream'}
                    response = await client.post('/mcp', json=body, headers=headers)
                    self.assertEqual(response.status_code, 200, response.text)
                    tools = response.json()['result']['tools']
                    self.assertEqual({tool['name'] for tool in tools}, {'platform_status', 'platform_overview', 'records', 'inventory'})
                    self.assertTrue(all(tool['annotations']['readOnlyHint'] for tool in tools))
                    call = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'platform_status', 'arguments': {}}}
                    self.assertFalse((await client.post('/mcp', json=call, headers=headers)).json()['result']['isError'])
                    call['params']['name'] = 'approve'
                    self.assertTrue((await client.post('/mcp', json=call, headers=headers)).json()['result']['isError'])
        asyncio.run(check())
