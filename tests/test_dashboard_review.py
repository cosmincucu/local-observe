import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from local_observe.deployment.content import Conflict
from local_observe.deployment.live import capture
from local_observe.inventory.validation import digest


def widget(identity='shared', sql='SELECT 1'):
    return {'id':identity, 'title':identity, 'panelTypes':'value',
            'query':{'queryType':'clickhouse_sql',
                     'clickhouse_sql':[{'name':'A','query':sql,'disabled':False,'legend':''}]}}


def panel(name='shared', sql='SELECT 1'):
    return {'kind':'Panel','spec':{'display':{'name':name},
            'plugin':{'kind':'signoz/NumberPanel','spec':{}},
            'queries':[{'kind':'time_series','spec':{'name':'A',
                'plugin':{'kind':'signoz/ClickHouseSQL',
                         'spec':{'name':'A','query':sql,'disabled':False,'legend':''}}}}]}}


def inputs():
    legacy = {'title':'Example','description':'','widgets':[widget()], 'layout':[], 'variables':{}}
    authoring = {'schema_version':1,'id':'example','content':[
        {'id':'user.example','kind':'dashboard','spec':legacy}], 'overrides':[],
        'homepage':{'title':'Example','theme':'dark','color':'green'}}
    documents = {'user.example':{'name':'example','schemaVersion':'v6','tags':[],
        'spec':{'display':{'name':'Example'},'panels':{'shared':panel()},'layouts':[], 'variables':[]}}}
    identities = {'user.example':'backend-id'}
    return authoring, snapshot(documents, identities), documents, identities


def snapshot(documents, identities):
    return capture('signoz-v2-v6','https://example.test',
                   {**{key:digest(value) for key,value in documents.items()},
                    '$identity-map':digest(identities)}, now=1)


class DashboardReviewTests(unittest.TestCase):
    def review(self, values):
        from local_observe.deployment.dashboard_review import review
        return review(*values)

    def test_equal_sql_never_claims_query_or_live_acceptance(self):
        values = inputs()
        before = copy.deepcopy(values)
        result = self.review(values)
        self.assertFalse(result['deploy_authorized'])
        self.assertFalse(result['query_equivalence_proven'])
        self.assertFalse(result['freshness_checked'])
        self.assertTrue(result['dashboards'][0]['panels']['sql'][0]['text_equal'])
        self.assertEqual(values, before)
        self.assertEqual(result, self.review(values))

    def test_added_removed_panels_sql_and_variables_are_named(self):
        authoring, _, documents, identities = inputs()
        legacy = authoring['content'][0]['spec']
        legacy['widgets'] += [widget('removed'), {'id':'heading','title':'Heading','panelTypes':'row'}]
        legacy['variables'] = {'uuid-key':{'name':'old','type':'TEXTBOX','textboxValue':'one'}}
        live = documents['user.example']['spec']
        live['panels']['shared'] = panel(sql='SELECT 2')
        live['panels']['added'] = panel('Added panel')
        live['variables'] = [{'kind':'TextVariable','spec':{'name':'new','value':'two'}}]
        result = self.review((authoring,snapshot(documents,identities),documents,identities))['dashboards'][0]
        self.assertEqual([p['id'] for p in result['panels']['added']], ['added'])
        self.assertEqual([p['id'] for p in result['panels']['removed']], ['removed'])
        self.assertFalse(result['panels']['sql'][0]['text_equal'])
        self.assertEqual(result['variables']['added'], ['new'])
        self.assertEqual(result['variables']['removed'], ['old'])

    def test_tampered_snapshot_document_or_identity_map_refused(self):
        for target in ('snapshot','document','identity'):
            values = inputs()
            if target == 'snapshot':
                values[1]['sha256'] = '0'*64
            elif target == 'document':
                values[2]['user.example']['spec']['unfamiliar'] = 'must be hashed'
            else:
                values[3]['user.example'] = 'substituted'
            with self.assertRaises(Conflict):
                self.review(values)

    def test_duplicates_and_unsupported_shapes_refused(self):
        for target in ('widget','content','variable','schema'):
            authoring, _, documents, identities = inputs()
            legacy = authoring['content'][0]['spec']
            if target == 'widget':
                legacy['widgets'].append(widget())
            elif target == 'content':
                authoring['content'].append(copy.deepcopy(authoring['content'][0]))
            elif target == 'variable':
                legacy['variables'] = {'one':{'name':'same'},'two':{'name':'same'}}
            else:
                documents['user.example']['schemaVersion'] = 'v99'
            with self.assertRaises(Conflict):
                self.review((authoring,snapshot(documents,identities),documents,identities))

    def test_missing_authoring_and_missing_live_are_not_silently_dropped(self):
        authoring, _, documents, identities = inputs()
        authoring['content'][0]['id'] = 'user.only-authoring'
        result = self.review((authoring,snapshot(documents,identities),documents,identities))
        self.assertEqual({r['id']:r['status'] for r in result['dashboards']},
                         {'user.example':'missing_authoring','user.only-authoring':'missing_live'})

    def test_cli_is_offline_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            args = []
            files = []
            for name, value in zip(('deployment','snapshot','documents','identities'),inputs()):
                path = Path(directory)/(name+'.json')
                path.write_text(json.dumps(value),encoding='utf-8')
                files.append((path,path.read_bytes()))
                args.extend(['--'+name,str(path)])
            result = subprocess.run([sys.executable,'-B','-m','local_observe.deployment.cli',
                                     'review-dashboards',*args],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['deploy_authorized'])
            for path, before in files:
                self.assertEqual(path.read_bytes(), before)

    def test_dashboard_override_refused_instead_of_comparing_unapplied_authoring(self):
        values = inputs()
        values[0]['overrides'] = [{'id':'user.example','expect_sha256':'0'*64,'mode':'disable'}]
        with self.assertRaises(Conflict):
            self.review(values)

    def test_same_sql_is_not_same_query_settings_or_unknown_plugin_fields(self):
        values = inputs()
        first = self.review(values)
        body = values[2]['user.example']['spec']['panels']['shared']['spec']
        body['queries'][0]['spec']['plugin']['spec']['disabled'] = True
        body['plugin']['spec']['unfamiliar'] = {'retain':True}
        values = (values[0],snapshot(values[2],values[3]),values[2],values[3])
        changed = self.review(values)
        self.assertTrue(changed['dashboards'][0]['panels']['sql'][0]['text_equal'])
        self.assertNotEqual(first['input_hashes']['documents'],changed['input_hashes']['documents'])
        self.assertNotEqual(first['dashboards'][0]['panels']['shared'][0]['queries'],
                            changed['dashboards'][0]['panels']['shared'][0]['queries'])
        self.assertFalse(changed['query_equivalence_proven'])

    def test_broken_layout_reference_refused(self):
        authoring, _, documents, identities = inputs()
        documents['user.example']['spec']['layouts'] = [{'kind':'Grid','spec':{'items':[
            {'content':{'$ref':'#/spec/panels/missing'},'x':0,'y':0,'width':3,'height':3}]}}]
        with self.assertRaises(Conflict):
            self.review((authoring,snapshot(documents,identities),documents,identities))

    def test_composite_query_without_outer_name_is_uninterpreted_not_equivalent(self):
        authoring, _, documents, identities = inputs()
        documents['user.example']['spec']['panels']['shared']['spec']['queries'] = [
            {'kind':'scalar','spec':{'plugin':{'kind':'signoz/CompositeQuery','spec':{'queries':[]}}}}]
        row = self.review((authoring,snapshot(documents,identities),documents,identities))['dashboards'][0]
        self.assertEqual(row['panels']['sql'], [])
        self.assertEqual(row['panels']['shared'][0]['sql_text_comparison'],'not-applicable-or-unsupported')
