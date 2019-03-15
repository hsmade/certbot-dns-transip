from unittest import TestCase
from transip.service.objects import DnsEntry
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util
from certbot_dns_transip.dns_transip import _TransipClient, Authenticator
import mock
import os
from tempfile import mktemp
from certbot.errors import PluginError
import logging

logging.getLogger(_TransipClient.__class__.__name__).setLevel('DEBUG')

USERNAME = 'foobar'
KEY_FILE = mktemp()


class Test_TransipClient(TestCase):
    def setUp(self):
        self.domain_service = mock.MagicMock()
        with open(KEY_FILE, 'w') as key_file:
            key_file.write('''-----BEGIN RSA PRIVATE KEY-----
foobar
-----END RSA PRIVATE KEY-----''')
        self.transip_client = _TransipClient(username=USERNAME, key_file=KEY_FILE)
        self.transip_client.domain_service = self.domain_service
        self.domain_service.get_domain_names.return_value = ['example.com']
        self.correct_entry1 = DnsEntry(name='record1', record_type='A', content='127.0.0.1', expire=1)
        self.correct_entry2 = DnsEntry(name='record2', record_type='TXT', content='f00b4r', expire=1)
        self.add_record = DnsEntry(name='test.test', record_type='TXT', content='new record', expire=1)

    def tearDown(self):
        os.unlink(KEY_FILE)

    def test_add_txt_record(self):
        self.domain_service.get_info = mock.MagicMock()

        class FakeGetInfo(object):
            dnsEntries = [self.correct_entry1, self.correct_entry2]
        self.domain_service.get_info.return_value = FakeGetInfo
        self.transip_client.add_txt_record(
            domain_name='example.com',
            record_content='new record',
            record_name='test.test.example.com'
        )
        self.domain_service.set_dns_entries.assert_called_once_with(domain_name='example.com', dns_entries=[
            self.correct_entry1,
            self.correct_entry2,
            self.add_record
        ])

    def test_del_txt_record(self):
        self.domain_service.get_info = mock.MagicMock()

        class FakeGetInfo(object):
            dnsEntries = [self.correct_entry1, self.add_record, self.correct_entry2]
        self.domain_service.get_info.return_value = FakeGetInfo
        self.transip_client.del_txt_record(
            domain_name='example.com',
            record_content='new record',
            record_name='test.test.example.com'
        )
        self.domain_service.set_dns_entries.assert_called_once_with(domain_name='example.com', dns_entries=[
            self.correct_entry1,
            self.correct_entry2,
        ])

    def test__get_dns_entries(self):
        self.domain_service.get_info = mock.MagicMock()

        class FakeGetInfo(object):
            dnsEntries = [self.correct_entry1, self.correct_entry2]
        self.domain_service.get_info.return_value = FakeGetInfo
        self.assertEquals(self.transip_client._get_dns_entries('example.com'), [self.correct_entry1, self.correct_entry2])

    def test__get_dns_entries_empty_result_list(self):
        self.domain_service.get_info = mock.MagicMock()

        class FakeGetInfo(object):
            dnsEntries = []
        self.domain_service.get_info.return_value = FakeGetInfo

        with self.assertRaises(PluginError):
            self.transip_client._get_dns_entries('example.com')

    def test__find_domain(self):
        self.assertEquals(self.transip_client._find_domain('example.com'), 'example.com')

    def test__find_domain_fail(self):
        self.domain_service.get_domain_names.return_value = ['example2.com']
        self.assertRaises(PluginError, self.transip_client._find_domain, 'example.com')

    def test__compute_record_name(self):
        self.assertEquals(_TransipClient._compute_record_name('example.com', 'record.sub.example.com'), 'record.sub')


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):
    def setUp(self):
        from certbot_dns_transip.dns_transip import Authenticator

        super(AuthenticatorTest, self).setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"transip_key_file": KEY_FILE, "transip_username": USERNAME}, path)

        self.config = mock.MagicMock(transip_credentials=path,
                                     transip_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "transip")

        self.mock_client = mock.MagicMock()
        # _get_transip_client | pylint: disable=protected-access
        self.auth._get_transip_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)
