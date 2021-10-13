# -*- coding: UTF-8 -*-
# File: dns_transip.py
"""certbot DNS plugin for Transip."""

import logging
import os
from tempfile import mktemp
from distutils.util import strtobool

import transip
import zope.interface
from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

__author__ = '''Wim Fournier <wim@fournier.nl>'''
__docformat__ = 'plaintext'
__date__ = '''14-07-2017'''

LOGGER = logging.getLogger(__name__)
TRANSIP_EXCEPTIONS = (
    transip.exceptions.TransIPError,
    transip.exceptions.TransIPHTTPError,
    transip.exceptions.TransIPIOError,
    transip.exceptions.TransIPParsingError
)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):

    """
    DNS Authenticator for Transip.

    This Authenticator uses the Transip API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Transip for DNS).'

    def __init__(self, *args, **kwargs):
        """Setup object."""
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.temp_file = None

    @classmethod
    def add_parser_arguments(cls, add, **_):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=240)
        add('credentials', help='Transip credentials INI file.')

    def more_info(self):
        """Returns info about this plugin."""
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Transip API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Transip credentials INI file',
            {
                'key_file': 'RSA key file'
                            '(convert with openssl rsa -in transip.key -out decrypted_key)',
                'username': 'Transip username',
            }
        )

    def _perform(self, domain, validation_name, validation):
        self.logger.debug('_perform: running adding txt record %s.%s', domain, validation_name)
        self._get_transip_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self.logger.debug('_cleanup: removing adding txt record %s.%s', domain, validation_name)
        try:
            self._get_transip_client().del_txt_record(domain, validation_name, validation)
        except Exception:
            if self.temp_file:
                os.unlink(self.temp_file)
            raise

    def _get_transip_client(self):
        username = self.credentials.conf('username')
        global_key = False
        try:
            global_key = bool(strtobool(self.credentials.conf('global_key')))
        except ValueError:
            raise ValueError("dns_transip_global_key should have either 'yes' or 'no' as value")
        except AttributeError:  # global_key was not present in the config, use default
            pass

        if not self.credentials.conf('key_file'):
            if self.credentials.conf('rsa_key'):
                key_file = mktemp()
                os.chmod(key_file, 600)
                with key_file as key:
                    key.write(self.credentials.conf('rsa_key'))
            else:
                raise ValueError('Please specify either an RSA key, or an RSA key file')
        else:
            key_file = self.credentials.conf('key_file')
        self.logger.debug('Creating Transip API client for user %s', username)
        return _TransipClient(username=username, key_file=key_file, global_key=global_key)


class _TransipClient:
    """Encapsulates all communication with the Transip API."""

    def __init__(self, username, key_file, global_key):
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.client = transip.TransIP(login=username, private_key_file=key_file, global_key=global_key)

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Transip API
        """
        canonical_domain = self._find_domain(domain_name)

        try:
            domain = self.client.domains.get(canonical_domain)
        except TRANSIP_EXCEPTIONS as error:
            raise errors.PluginError('Error finding domain using the Transip API: {0}'.format(error))

        new_record = {
            "name": self._compute_record_name(canonical_domain, record_name),
            "type": "TXT",
            "content": record_content,
            "expire": 1,
        }

        try:
            domain.dns.create(new_record)
        except TRANSIP_EXCEPTIONS as error:
            raise errors.PluginError('Error finding domain using the Transip API: {0}'.format(error))

    def del_txt_record(self, domain_name, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """
        canonical_domain = self._find_domain(domain_name)

        try:
            domain = self.client.domains.get(canonical_domain)
        except TRANSIP_EXCEPTIONS as error:
            raise errors.PluginError('Error finding domain using the Transip API: {0}'.format(error))

        delete_record = {
            "name": self._compute_record_name(canonical_domain, record_name),
            "type": "TXT",
            "content": record_content,
            "expire": 1,
        }

        try:
            domain.dns.delete(delete_record)
        except TRANSIP_EXCEPTIONS as error:
            raise errors.PluginError('Error finding domain using the Transip API: {0}'.format(error))

    def _find_domain(self, domain_name):
        """
        Find the domain object for a given domain name.

        :param str domain_name: The domain name for which to find the corresponding Domain.
        :returns: The Domain, if found.
        :rtype: `str`
        :raises certbot.errors.PluginError: if no matching Domain is found.
        """
        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        try:
            domains = [item.name for item in self.client.domains.list()]
        except TRANSIP_EXCEPTIONS as error:
            raise errors.PluginError('Error finding domain using the Transip API: {0}'.format(error))

        if not domains:
            raise errors.PluginError("Transip API returned no domains")

        for guess in domain_name_guesses:
            if guess in domains:
                self.logger.debug('Found base domain for %s using name %s', domain_name, guess)
                return guess

        raise errors.PluginError('Unable to determine base domain for {0} using names: {1} and domains: {2}.'
                                 .format(domain_name, domain_name_guesses, domains))

    @staticmethod
    def _compute_record_name(domain, full_record_name):
        # The domain, from Transip's point of view, is automatically appended.
        return full_record_name.rpartition("." + domain)[0]
