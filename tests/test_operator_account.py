import base64
import hashlib
import json
from pathlib import Path
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from local_observe.platform import operator_account as accounts


class AccountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = '  p\u00e4ss:\U0001f511  '
        cls.account = accounts.make_account('alice', cls.password)

    def test_hash_contract_and_utf8(self):
        account = self.account
        self.assertEqual(set(account), accounts.ACCOUNT_KEYS)
        self.assertEqual(account['identity'], 'operator')
        self.assertEqual(account['iterations'], 600000)
        self.assertEqual(len(bytes.fromhex(account['salt'])), 16)
        expected = hashlib.pbkdf2_hmac('sha256', self.password.encode(), bytes.fromhex(account['salt']),600000).hex()
        self.assertEqual(account['password_hash'],expected)
        self.assertTrue(accounts.verify_password(account,'alice',self.password))
        self.assertFalse(accounts.verify_password(account,'wrong',self.password))
        self.assertFalse(accounts.verify_password(account,'alice','wrong'))
        self.assertNotIn(self.password,json.dumps(account))

    def test_account_input_bounds(self):
        for user in ['', '_first', 'a:b', 'alice\n', '\u00e9', 'a'*65]:
            with self.subTest(user=user), self.assertRaises(ValueError): accounts.make_account(user,'ok')
        for password in ['', 'a\rb', 'a\nb', 'a\0b', '\ud800', '\u00e9'*513]:
            with self.subTest(), self.assertRaises(ValueError): accounts.make_account('alice',password)
        account = accounts.make_account('a', '\u00e9'*512)
        self.assertTrue(accounts.verify_password(account,'a','\u00e9'*512))

    def test_strict_bounded_file_and_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'account.json'
            path.write_text(json.dumps(self.account),encoding='utf-8')
            self.assertEqual(accounts.load_account(path),self.account)
            self.assertIsNone(accounts.account_from_environment({}))
            self.assertEqual(accounts.account_from_environment({'LO_OPERATOR_ACCOUNT_FILE':str(path)}),self.account)
            invalid = ['{invalid secret', 'x'*8193, '[]', '{"schema":1,"schema":1}', '['*2000 + ']'*2000]
            for key, value in [('schema',True),('schema',1.0),('iterations',600000.0),('iterations',1),('salt','00'),('identity','\ud800'),('extra','secret')]:
                invalid.append(json.dumps({**self.account,key:value}))
            invalid.append(json.dumps(self.account)[:-1]+',"username":"alice"}')
            for raw in invalid:
                path.write_text(raw,encoding='utf-8')
                with self.subTest(raw=raw[:20]), self.assertRaises(ValueError) as error:
                    accounts.load_account(path)
                self.assertEqual(str(error.exception),accounts.MALFORMED_ACCOUNT)
            with self.assertRaises(ValueError): accounts.load_account(Path(tmp)/'missing')
            with self.assertRaises(ValueError): accounts.account_from_environment({'LO_OPERATOR_ACCOUNT_FILE':' '})

    def test_basic_strict_decoding(self):
        def basic(raw): return 'Basic '+base64.b64encode(raw).decode()
        self.assertEqual(accounts.parse_basic(basic(('alice:'+self.password).encode())),('alice',self.password))
        for header in ['Basic !!!','Basic YTpi\n','Basic '+('YQ=='*1000),basic(b'a'),basic(b'a:'),basic(b':p'),basic(b'a:p\0'),basic(b'a:\xff'),basic(b'a:'+b'x'*2049)]:
            with self.subTest(header=header[:20]): self.assertIsNone(accounts.parse_basic(header))

    def test_non_regular_account_is_refused_before_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'account.json'
            path.write_text(json.dumps(self.account),encoding='utf-8')
            with patch.object(accounts.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFIFO)):
                with self.assertRaisesRegex(ValueError,accounts.MALFORMED_ACCOUNT): accounts.load_account(path)

    def test_identity_binding(self):
        human = {'identity':'operator','role':'human','token':'test-bearer'}
        self.assertEqual(accounts.human_bearer([human],self.account),'test-bearer')
        other = {**human, 'identity': 'other-human', 'token': 'other-bearer'}
        for rows in ([human, other], [other, human]):
            self.assertEqual(accounts.human_bearer(rows, self.account), 'test-bearer')
        with self.assertRaises(ValueError):
            accounts.human_bearer([other, {**human, 'role': 'reader'}], self.account)
        for rows in [[],[{**human,'role':'reader'}],[{**human,'identity':'other'}],[human,human]]:
            with self.assertRaises(ValueError): accounts.human_bearer(rows,self.account)
