from unittest import TestCase

import certbot
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util
from certbot_dns_transip.dns_transip import _TransipClient
import mock
import os
from tempfile import mktemp
from certbot.errors import PluginError
import logging

logging.getLogger(_TransipClient.__class__.__name__).setLevel('DEBUG')

USERNAME = 'foobar'
KEY_FILE = mktemp()


# wrap the class we want to test, to remove the client init in __init__ (as it will break)
class _TransipClientTest(_TransipClient):
    def __init__(self):
        self.logger = logging.getLogger(__name__)


class _DomainMock:
    def __init__(self, name):
        self.name = name


class Test_TransipClient(TestCase):
    def setUp(self):
        self.client = mock.MagicMock()
        with open(KEY_FILE, 'w') as key_file:
            key_file.write('''-----BEGIN RSA PRIVATE KEY-----
foobar
-----END RSA PRIVATE KEY-----''')
        self.transip_client = _TransipClientTest()
        self.transip_client.client = self.client
        self.transip_client.client.domains = self.client
        self.transip_client.client.domains.list.return_value = [_DomainMock(name="example.com")]
        self.add_record = {"name": "test.test", "type": "TXT", "content": "new record", "expire": 1}

    def tearDown(self):
        os.unlink(KEY_FILE)

    def test_add_txt_record(self):
        domain = mock.MagicMock()

        self.client.domains.get.return_value = domain
        self.transip_client.add_txt_record(
            domain_name='example.com',
            record_content='new record',
            record_name='test.test.example.com'
        )
        domain.dns.create.assert_called_once_with(self.add_record)

    def test_del_txt_record(self):
        domain = mock.MagicMock()

        self.client.domains.get.return_value = domain
        self.transip_client.del_txt_record(
            domain_name='example.com',
            record_content='new record',
            record_name='test.test.example.com'
        )
        domain.dns.delete.assert_called_once_with(self.add_record)

    def test__find_domain(self):
        self.assertEquals(self.transip_client._find_domain('example.com'), 'example.com')

    def test__find_domain_fail(self):
        self.assertRaises(PluginError, self.transip_client._find_domain, 'example2.com')

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
        certbot._internal.display.obj.get_display = mock.MagicMock()
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)
