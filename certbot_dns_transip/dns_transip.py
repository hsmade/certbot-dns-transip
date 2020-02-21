#!/usr/bin/env python2.7
# -*- coding: UTF-8 -*-
# File: dns_transip.py
"""certbot DNS plugin for Transip"""

import logging
import os
import time
from tempfile import mktemp

from transip.service.objects import DnsEntry
from transip.service.domain import DomainService
import suds
import zope.interface
from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

__author__ = '''Wim Fournier <wim@fournier.nl>'''
__docformat__ = 'plaintext'
__date__ = '''14-07-2017'''

logger = logging.getLogger(__name__)
# There seems to be a bug with suds where it tries to access invalid attributes on logging
logging.getLogger('suds').setLevel('WARNING')


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Transip

    This Authenticator uses the Transip API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certs using a DNS TXT record (if you are using Transip for DNS).'

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.logger = logger.getChild(self.__class__.__name__)
        self.temp_file = None

    @classmethod
    def add_parser_arguments(cls, add, **kwargs):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=240)
        add('credentials', help='Transip credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
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
        return _TransipClient(username=username, key_file=key_file)


class _TransipClient(object):
    """Encapsulates all communication with the Transip API."""

    def __init__(self, username, key_file):
        self.logger = logger.getChild(self.__class__.__name__)
        self.domain_service = DomainService(login=username, private_key_file=key_file)

    def add_txt_record(self, domain_name, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain_name: The domain to use to associate the record with.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Transip
                                            API
        """
        try:
            domain = self._find_domain(domain_name)
        except suds.WebFault as e:
            self.logger.error('Error finding domain using the Transip API: %s', e)
            raise errors.PluginError('Error finding domain using the Transip API: {0}'
                                     .format(e))

        domain_records = self._get_dns_entries(domain)

        try:
            new_record = DnsEntry(
                name=self._compute_record_name(domain, record_name),
                record_type='TXT',
                content=record_content,
                expire=1,
            )
        except suds.WebFault as e:
            self.logger.error('Error getting DNS records using the Transip API: %s', e)
            return

        domain_records.append(new_record)

        try:
            self.domain_service.set_dns_entries(domain_name=domain, dns_entries=domain_records)
            self.logger.info('Successfully added TXT record')
        except suds.WebFault as e:
            self.logger.error('Error adding TXT record using the Transip API: %s', e)
            raise errors.PluginError('Error adding TXT record using the Transip API: {0}'
                                     .format(e))

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
        try:
            domain = self._find_domain(domain_name)
        except suds.WebFault as e:
            self.logger.error('Error finding domain using the Transip API: %s', e)
            return

        domain_records = self._get_dns_entries(domain)

        matching_records = [record for record in domain_records
                            if record.type == 'TXT'
                            and record.name == self._compute_record_name(domain, record_name)
                            and record.content == record_content]

        for record in matching_records:
            self.logger.info('Removing TXT record with name: %s', record.name)
            del domain_records[domain_records.index(record)]

        try:
            self.domain_service.set_dns_entries(domain_name=domain, dns_entries=domain_records)
        except suds.WebFault as e:
            self.logger.error('Error while storing DNS records: %s', e)

    def _get_dns_entries(self, domain, retries=3, backoff=5):
        """
        Get all DNS entries for this domain.

        :param str domain: The domain to use to associate the record with.
        :raises certbot.errors.PluginError: if an error occurs communicating with the Transip
                                            API
        """
        dns_entries = []
        for retry in range(retries + 1):
            try:
                dns_entries = self.domain_service.get_info(domain_name=domain).dnsEntries
            except suds.WebFault as e:
                self.logger.error('Error getting DNS records using the Transip API: %s', e)
                raise errors.PluginError('Error finding DNS entries using the Transip API: {0}'
                                         .format(domain))
            if dns_entries:
                break
            self.logger.warning('Error getting DNS records using the Transip API: retry in {} seconds'.format(
                backoff
            ))
            time.sleep(backoff)
            backoff = backoff * 2

        # If there are still no entries then the Transip API returned the wrong data
        if not dns_entries:
            error = 'Error finding DNS entries using the Transip API: Empty record set for {}'.format(domain)
            self.logger.error(error)
            raise errors.PluginError(error)

        return dns_entries

    def _find_domain(self, domain_name):
        """
        Find the domain object for a given domain name.

        :param str domain_name: The domain name for which to find the corresponding Domain.
        :returns: The Domain, if found.
        :rtype: `str`
        :raises certbot.errors.PluginError: if no matching Domain is found.
        """
        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)

        domains = self.domain_service.get_domain_names()

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
