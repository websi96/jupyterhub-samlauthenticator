'''
(C) Copyright 2019 Hewlett Packard Enterprise Development LP

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

""" OneLogin_Saml2_Auth class
Copyright (c) 2010-2018 OneLogin, Inc.
MIT License
Main class of OneLogin's Python Toolkit.
Initializes the SP SAML instance
"""
'''

# Imports from python standard library
from base64 import b64decode, b64encode
from datetime import datetime, timezone, timedelta
from urllib.request import urlopen
from urllib import parse

import asyncio
import pwd
import subprocess

# Imports to work with JupyterHub
from jupyterhub.auth import Authenticator
from jupyterhub.utils import maybe_future
from jupyterhub.handlers.base import BaseHandler
from jupyterhub.handlers.login import LoginHandler, LogoutHandler
from tornado import gen, web, httputil
from traitlets import Unicode, Bool
from jinja2 import Template

# Imports for me
from lxml import etree
import pytz
from signxml import XMLVerifier
import zlib
import uuid
import hashlib
from io import StringIO
# python3-saml
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.errors import OneLogin_Saml2_Error
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.response import OneLogin_Saml2_Response
import xmlsec


class SAMLAuthenticator(Authenticator):
    auth_version = Unicode(
        default_value='v2',
        allow_none=True,
        config=True,
        help='''
        Change between onelogin (v2) version and self scripted version (v1).
        '''
    )
    use_signing = Bool(
        default_value=False,
        allow_none=True,
        config=True,
        help='''
        Set if Authnrequest should be signed. And response validated.
        '''
    )
    cert_content = Unicode(
        default_value='''-----BEGIN CERTIFICATE-----
MIIDZTCCAk2gAwIBAgIUAggg3MKYR2S+qJB/l4hlVqZKH7IwDQYJKoZIhvcNAQEL
BQAwQjELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UE
CgwTRGVmYXVsdCBDb21wYW55IEx0ZDAeFw0yMDA5MDExMDEwMjhaFw0yMDEwMDEx
MDEwMjhaMEIxCzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAa
BgNVBAoME0RlZmF1bHQgQ29tcGFueSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCXTTD/NLl/IlxSGn7C8Arv67om678FEGpVGhWWnaoOwu4wOTPD
Z/EblCiM5IuiGKSU7aQji5HGeu8uALuwFhqlTiQg2r7jMrUio0tK+eUnJSXFLQwu
AumHYXZLKSXFiBmiGIKENz5zp+o9leVFJij+9QOZNQq+o+AkZwHaaO6FZ8jNWt/e
BTf7w8YT4azqqJaw3SypQYIIu2cMnoZAThAjsYzNxzVLR2KJJe/p76Z5mKzBw9/E
V6DbRWZ6hh1awj2F3VwH8DnKf1JCHAqOqTz4y7ddIcXux3HiCR0BNBygS8HZC7JJ
lPMDj4LTJQ9VP6uT77V36ovynA1+UMVrVQLvAgMBAAGjUzBRMB0GA1UdDgQWBBTY
uYzlIv+2M7TXIY/x94YCIh38qjAfBgNVHSMEGDAWgBTYuYzlIv+2M7TXIY/x94YC
Ih38qjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBFd1DeNO0n
4aWrcE1onso35P0bnO1jvU5xAmMWVuo2aODyDVzlI6XxnrO7LuY1J7jYiShjj2QB
Nfm7polHz35XogoWUSgWjsPBZrX+HpUbIk5eCtzqY8l/doBT6nWg4R3oqwfU+MdN
1HzPIoaL9reUKv4mYsv5wAKbz2PoH5uFaMSSfymy8fYrGiZFZIHfSMbeWIqZq8Iv
MtcMjq66h4PrCgFaaQ2mt6UYv5NP74UEpbbwOMfZm+2hbJau5OT2gHdFuhLITu4C
RMQMjaxUqYgEqFokIl5L9fuHW9EEQmKXlV3AdcmQcuf/gkCuTiKYxg/Od4r2CeIZ
SpZwwE1/+eeN
-----END CERTIFICATE-----''',
        allow_none=True,
        config=True,
        help='''
        Provide a Certificate for encryption and signing
        '''
    )
    cert_filepath = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        Provide a Certificate for encryption and signing
        '''
    )
    key_content = Unicode(
        default_value='''-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCXTTD/NLl/IlxS
Gn7C8Arv67om678FEGpVGhWWnaoOwu4wOTPDZ/EblCiM5IuiGKSU7aQji5HGeu8u
ALuwFhqlTiQg2r7jMrUio0tK+eUnJSXFLQwuAumHYXZLKSXFiBmiGIKENz5zp+o9
leVFJij+9QOZNQq+o+AkZwHaaO6FZ8jNWt/eBTf7w8YT4azqqJaw3SypQYIIu2cM
noZAThAjsYzNxzVLR2KJJe/p76Z5mKzBw9/EV6DbRWZ6hh1awj2F3VwH8DnKf1JC
HAqOqTz4y7ddIcXux3HiCR0BNBygS8HZC7JJlPMDj4LTJQ9VP6uT77V36ovynA1+
UMVrVQLvAgMBAAECggEAc7renIbm0GEm/sI3bcKQix3jILw4O5ZnzzqJgtCMcIgY
CxjmCDSsTy0Pq11xlQaGdUgkwe+TDJ+h7a0v4yu1K/ZOWjcXxc9Wj+0ZvXrSFhQr
BNxFMbiWijA5fJo3wxUsjjlzM9DR20N4P601VqQuvX4KR5kz48iTvSRxXW/f6nfg
Dk1NfcHkJz321raI1KUTzAD1wq4pEsh8L7cLrchEX9vDsTaQ0mzW0OWpkGUWJm2r
5e8RFnqE4w+ZdPoC2bVrXVRK5bA8dTv53i9JaCDyoBi44gYIHLGbAQM58zyjaNA/
AYLD0RyZDN5wzOc6MFEZZniE3u+15BT5m8hXD+WxuQKBgQDJcfr+V0Nb8loTfJuK
h9O3GwsT6jF95vfqBuV/06BsuBT1lTf+WPnbqt1GxSMsWbtWfu2jLSBQ4AFtb1dV
NJArTVH3zsbNPCF/KnjNzGTb2vSWffIIPFQDLO2esWtTxwU9lU4rq2u8N3WXYGZU
hHlfkfaXM0sseiDtI9lrNIlYywKBgQDARsrNuMlwQa3kzDmHJI3lf59ge9Yz+l8w
xCexbWtGPZfnqetd+l5FWA8Ib9HcqcKOGzFY8OTXJ/vGZsa/GfFkkybKf20Jo78e
iN2IqNK2ge6tE2y0oPYjV8ds0DUtwI4ZlZQP1rzFEi4AXn8P/+tZLi7tVlXMv11H
UIihLBKN7QKBgQC1n159EpBYxhkQmLhkHjJ0VJ2YRv54VVYQWkdxCI0LeKzs/qyN
VgtwUo1O0U71HbIaOjZneLg6Mr0WvdwvpkSVxhCxLG1xfVV2IgTpB++nibIcPVGK
u1nDwy46dhweXMIM1CC2nsdz20zaPsAEU6xazm9Vw5lzcGlfZYMRdTygIQKBgQCS
+wq4rBNAftShXAR17FmUIDUDGmcqILB3pNr65LvmW9stOlUz59n8hE4pkuEIH7Ub
0GmupacpWeU7SwGOwBQpX9t9XF9LySKmAtXmS7eX0EdVgs3MXmcJqWZHJfog2VtG
73LZkLuIolcL7TCQWH/eElHJGABKndZ+V2+6VOhyGQKBgC367tYU7FKMW0gnCFkB
NezyF8t3pssGmn1uE0bRwe2bmITWaUt0B2EqI0Xbo02vqsfICDtBitxgNHi0J187
aT/94klm9MOcK+3sSKqdvrXgN4f8DD631utkkahED1ArxcDDsb75P0XToKnJGeul
BqyvsK6SXsj16MuGXHDgiJNN
-----END PRIVATE KEY-----''',
        allow_none=True,
        config=True,
        help='''
        Provide a Key for encryption and signing
        '''
    )
    key_filepath = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        Provide a Key for encryption and signing
        '''
    )
    metadata_filepath = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A filepath to the location of the SAML IdP metadata. This is the most preferable
        option for presenting an IdP's metadata to the authenticator.
        '''
    )
    metadata_content = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A fully-inlined version of the SAML IdP metadata. Mostly provided for testing,
        but if you want to use this for a "production-type" system, I'm not going to
        judge. This is preferred above getting metadata from a web-request, but not
        preferred above getting the metadata from a file.
        '''
    )
    metadata_url = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A URL where the SAML Authenticator can find metadata for the SAML IdP. This is
        the least preferable method of providing the SAML IdP metadata to the
        authenticator, as it is both slow and vulnerable to Man in the Middle attacks,
        including DNS poisoning.
        '''
    )
    xpath_username_location = Unicode(
        default_value='//saml:NameID/text()',
        allow_none=True,
        config=True,
        help='''
        This is an XPath that specifies where the user's name or id is located in the
        SAML Assertion. This is partly for testing purposes, but there are cases where
        an administrator may want a user to be identified by their email address instead
        of an LDAP DN or another string that comes in the NameID field. The namespace
        bindings when executing the XPath will be as follows:

        {
            'ds'   : 'http://www.w3.org/2000/09/xmldsig#',
            'md'   : 'urn:oasis:names:tc:SAML:2.0:metadata',
            'saml' : 'urn:oasis:names:tc:SAML:2.0:assertion',
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
        }
        '''
    )
    login_post_field = Unicode(
        default_value='SAMLResponse',
        allow_none=False,
        config=True,
        help='''
        This value specifies what field in the SAML Post request contains the Base-64
        encoded SAML Response.
        '''
    )
    audience = Unicode(
        default_value=None,
        allow_none=True,
        config=True,
        help='''
        The SAML Audience must be configured in the SAML IdP. This value ensures that a
        SAML assertion cannot be used by a malicious service to authenticate to a naive
        service. If this value is not set in the configuration file or if the string
        provided is a "false-y" value in python, this will not be checked.
        '''
    )
    recipient = Unicode(
        default_value=None,
        allow_none=True,
        config=True,
        help='''
        The SAML Recipient must be configured in the SAML IdP. This value ensures that a
        SAML assertion cannot be used by a malicious service to authenticate to a naive
        service. If this value is not set in the configuration file or if the string
        provided is a "false-y" value in python, this will not be checked.
        '''
    )
    time_format_string = Unicode(
        default_value='%Y-%m-%dT%H:%M:%SZ',
        allow_none=False,
        config=True,
        help='''
        A time format string that complies with python's strftime()/strptime() behavior.
        For more information on this format, please read the information at the
        following link:

        https://docs.python.org/3/library/datetime.html#strftime-and-strptime-behavior

        '''
    )
    idp_timezone = Unicode(
        default_value='UTC',
        allow_none=True,
        config=True,
        help='''
        A timezone-specific string that uniquely identifies a timezone using pytz's
        timezone constructor. To view a list of options, import the package and
        inspect the `pytz.all_timezones` list. It is quite long. For more information
        on pytz, please read peruse the pip package:

        https://pypi.org/project/pytz/

        '''
    )
    shutdown_on_logout = Bool(
        default_value=False,
        allow_none=False,
        config=True,
        help='''
        If you would like to shutdown user servers on logout, you can enable this
        behavior with:

        c.SAMLAuthenticator.shutdown_on_logout = True

        Be careful with this setting because logging out one browser does not mean
        the user is no longer actively using their server from another machine.

        It is a little odd to have this property on the Authenticator object, but
        (for internal-detail-reasons) since we need to hand-craft the LogoutHandler
        class, this should be on the Authenticator.
        '''
    )
    slo_forwad_on_logout = Bool(
        default_value=True,
        allow_none=False,
        config=True,
        help='''
        [DEPRECATED] Please use `slo_forward_on_logout`.
        This attribute will be removed in the next version.
        See https://github.com/bluedatainc/jupyterhub-samlauthenticator/releases/tag/samlauthenticator-0.0.7
        for more information.
        '''
    )
    slo_forward_on_logout = Bool(
        default_value=True,
        allow_none=False,
        config=True,
        help='''
        To prevent forwarding users to the SLO URI on logout,
        set this parameter to False like so:

        c.SAMLAuthenticator.slo_forward_on_logout = False
        '''
    )
    entity_id = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        The entity id for this specific JupyterHub instance. If
        populated, this will be included in the SP metadata as
        the entity id. If this is not populated, the entity will
        populate as the protocol, host, and port of the request
        to get the SAML Metadata.

        Note that if the JupyterHub server will be behind a
        proxy, this should be populated as the protocol, host,
        and port where the server can be reached. For example,
        if the JupyterHub server should be reached at
        10.0.31.2:8000, this should be populated as
        'https://10.0.31.2:8000'
        '''
    )
    nameid_format = Unicode(
        default_value='urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        allow_none=True,
        config=True,
        help='''
        The nameId format to set in the Jupyter SAML Metadata.
        Defaults to transient nameid-format, but other values such as
        urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress or
        urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
        are available. See section 8.3 of the spec
        http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
        for more details.
        '''
    )
    acs_endpoint_url = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        The access consumer endpoint url for this specific
        JupyterHub instance. If populated, this will be
        included in the SP metadata as the acs endpoint
        location. If populated, this field MUST tell the
        SAML IdP to post to the ip address and port the
        JupyterHub is running on concatenated to
        "/hub/login". For example, if the server were
        running on 10.0.31.2:8000, this value should be
        'https://10.0.31.2:8000/hub/login'. It is necessary
        to populate this field if the ACS Endpoint is
        significantly different from the entity id.
        If this is not populated, the entity location
        will populate as the entity id concatenated
        to '/hub/login'.
        '''
    )
    organization_name = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A short-form organization name. Will be populated into the
        SP metadata.
        '''
    )
    organization_display_name = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A long-form organization name. Will be populated into the
        SP metadata.
        '''
    )
    organization_url = Unicode(
        default_value='',
        allow_none=True,
        config=True,
        help='''
        A URL that uniquely identifies the organization.
        '''
    )
    create_system_users = Bool(
        default_value=True,
        allow_none=False,
        config=True,
        help='''
        When True, SAMLAuthenticator will create system users
        on user authentication if they don't exist already.
        Default value is True.
        '''
    )
    create_system_user_binary = Unicode(
        default_value='useradd',
        allow_none=True,
        config=True,
        help='''
        When SAMLAuthenticator creates a system user (also called "just in time user provisioning")
        it calls the binary specified in this property in a subprocess to perform the user creation.
        Default value is 'useradd'.
        This can be set to any binary in the host machine's PATH or a full path to an alternate
        binary not in the host's path. This binary MUST accpet calls of the form
        "${binary_name} ${user_name}" and exit with a status of zero on valid user addition or
        a non-zero status in the failure case.
        '''
    )
    xpath_role_location = Unicode(
        default_value=None,
        allow_none=True,
        config=True,
        help='''
        This is an XPath that specifies where the user's roles are located in
        the SAML  Assertion. This is to restrict users with certain roles
        granted by the administrator to have access to jupyterhub.
        '''
    )
    allowed_roles = Unicode(
        default_value=None,
        allow_none=True,
        config=True,
        help='''
        Comma-separated list of roles. SAMLAuthenticator will restrict access to
        jupyterhub to these roles if specified.
        '''
    )
    _const_warn_explain = 'Because no user would be allowed to log in via roles, role check disabled.'
    _const_warn_no_role_xpath = 'Allowed roles set while role location XPath is not set.'
    _const_warn_no_roles = 'Allowed roles not set while role location XPath is set.'

    def _get_metadata_from_file(self):
        with open(self.metadata_filepath, 'r') as saml_metadata:
            return saml_metadata.read()

    def _get_metadata_from_config(self):
        return self.metadata_content

    def _get_metadata_from_url(self):
        with urlopen(self.metadata_url) as remote_metadata:
            return remote_metadata.read()

    def _get_preferred_metadata_from_source(self):
        if self.metadata_filepath:
            return self._get_metadata_from_file()

        if self.metadata_content:
            return self._get_metadata_from_config()

        if self.metadata_url:
            return self._get_metadata_from_url()

        return None

    def _get_cert_from_file(self):
        with open(self.cert_filepath, 'r') as cert:
            return cert.read()

    def _get_cert_from_config(self):
        return self.cert_content

    def _get_key_from_file(self):
        with open(self.key_filepath, 'r') as key:
            return key.read()

    def _get_key_from_config(self):
        return self.key_content

    def _get_preferred_cert_from_source(self, format=False):
        if self.cert_filepath:
            if format:
                return OneLogin_Saml2_Utils.format_cert(self._get_cert_from_file())
            return self._get_cert_from_file()

        if self.cert_content:
            if format:
                return OneLogin_Saml2_Utils.format_cert(self._get_cert_from_config())
            return self._get_cert_from_config()

        return None

    def _get_preferred_key_from_source(self, format=False):
        if self.key_filepath:
            if format:
                return OneLogin_Saml2_Utils.format_private_key(self._get_key_from_file())
            return self._get_key_from_file()

        if self.key_content:
            if format:
                return OneLogin_Saml2_Utils.format_private_key(self._get_key_from_config())
            return self._get_key_from_config()

        return None

    def _log_exception_error(self, exception):
        self.log.warning('Exception: %s', str(exception))

    def _get_saml_doc_etree(self, data):
        saml_response = data.get(self.login_post_field, None)

        if not saml_response:
            # Failed to get the SAML Response from the posted data
            self.log.warning('Could not get SAML Response from post data')
            self.log.warning(
                'Expected SAML response in field %s', self.login_post_field)
            self.log.warning('Posted login data %s', str(data))
            return None

        decoded_saml_doc = None

        try:
            decoded_saml_doc = b64decode(saml_response)
        except Exception as e:
            # There was a problem base64 decoding the xml document from the posted data
            self.log.warning(
                'Got exception when attempting to decode SAML response')
            self.log.warning('Saml Response: %s', saml_response)
            self._log_exception_error(e)
            return None

        try:
            return etree.fromstring(decoded_saml_doc)
        except Exception as e:
            self.log.warning(
                'Got exception when attempting to hydrate response to etree')
            self.log.warning('Saml Response: %s', decoded_saml_doc)
            self._log_exception_error(e)
            return None

    def _get_saml_metadata_etree(self):
        try:
            saml_metadata = self._get_preferred_metadata_from_source()
        except Exception as e:
            # There was a problem getting the SAML metadata
            self.log.warning(
                'Got exception when attempting to read SAML metadata')
            self.log.warning('Ensure that EXACTLY ONE of metadata_filepath, ' +
                             'metadata_content, and metadata_url is populated')
            self._log_exception_error(e)
            return None

        if not saml_metadata:
            # There was a problem getting the SAML metadata
            self.log.warning(
                'Got exception when attempting to read SAML metadata')
            self.log.warning('Ensure that EXACTLY ONE of metadata_filepath, ' +
                             'metadata_content, and metadata_url is populated')
            self.log.warning('SAML metadata was empty')
            return None

        metadata_etree = None

        try:
            metadata_etree = etree.fromstring(saml_metadata)
        except Exception as e:
            # Failed to parse SAML Metadata
            self.log.warning(
                'Got exception when attempting to parse SAML metadata')
            self._log_exception_error(e)

        return metadata_etree

    def _make_xpath_builder(self):
        namespaces = {
            'ds': 'http://www.w3.org/2000/09/xmldsig#',
            'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
            'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
            'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'
        }

        def xpath_with_namespaces(xpath_str):
            return etree.XPath(xpath_str, namespaces=namespaces)

        return xpath_with_namespaces

    def _is_date_aware(self, created_datetime):
        return created_datetime.tzinfo is not None and \
            created_datetime.tzinfo.utcoffset(created_datetime) is not None

    def _verify_physical_constraints(self, signed_xml):
        xpath_with_namespaces = self._make_xpath_builder()

        find_not_before = xpath_with_namespaces('//saml:Conditions/@NotBefore')
        find_not_on_or_after = xpath_with_namespaces(
            '//saml:Conditions/@NotOnOrAfter')

        not_before_list = find_not_before(signed_xml)
        not_on_or_after_list = find_not_on_or_after(signed_xml)

        if not_before_list and not_on_or_after_list:

            not_before_datetime = datetime.strptime(
                not_before_list[0], self.time_format_string)
            not_on_or_after_datetime = datetime.strptime(
                not_on_or_after_list[0], self.time_format_string)

            timezone_obj = None

            if not self._is_date_aware(not_before_datetime):
                timezone_obj = pytz.timezone(self.idp_timezone)
                not_before_datetime = timezone_obj.localize(
                    not_before_datetime)

            if not self._is_date_aware(not_on_or_after_datetime):
                if not timezone_obj:
                    timezone_obj = pytz.timezone(self.idp_timezone)
                not_on_or_after_datetime = timezone_obj.localize(
                    not_on_or_after_datetime)

            now = datetime.now(timezone.utc)

            if now < not_before_datetime or now >= not_on_or_after_datetime:
                self.log.warning('Bad timing condition')
                if now < not_before_datetime:
                    self.log.warning(
                        'Sent SAML Response before it was permitted')
                if now >= not_on_or_after_datetime:
                    self.log.warning(
                        'Sent SAML Response after it was permitted')
                return False
        else:
            self.log.warning(
                'SAML assertion did not contain proper conditions')
            if not not_before_list:
                self.log.warning(
                    'SAML assertion must have NotBefore annotation in Conditions')
            if not not_on_or_after_list:
                self.log.warning(
                    'SAML assertion must have NotOnOrAfter annotation in Conditions')
            return False

        return True

    def _get_username_from_saml_etree(self, signed_xml):
        xpath_with_namespaces = self._make_xpath_builder()

        xpath_fun = xpath_with_namespaces(self.xpath_username_location)
        xpath_result = xpath_fun(signed_xml)

        if isinstance(xpath_result, etree._ElementUnicodeResult):
            return xpath_result
        if type(xpath_result) is list and len(xpath_result) > 0:
            return xpath_result[0]

        self.log.warning('Could not find name from name XPath')
        return None

    def _get_roles_from_saml_etree(self, signed_xml):
        if self.xpath_role_location:
            xpath_with_namespaces = self._make_xpath_builder()
            xpath_fun = xpath_with_namespaces(self.xpath_role_location)
            xpath_result = xpath_fun(signed_xml)

            if xpath_result:
                return xpath_result

            self.log.warning('Could not find role from role XPath')

        return []

    def _get_username_from_saml_doc(self, signed_xml):
        user_name = self._get_username_from_saml_etree(signed_xml)
        if user_name:
            return user_name

        self.log.error('Did not get user name from signed SAML Response')

        return None

    def _get_roles_from_saml_doc(self, signed_xml):
        user_roles = self._get_roles_from_saml_etree(signed_xml)
        if user_roles:
            return user_roles

        self.log.error('Did not get user roles from signed SAML Response')

        return None

    def _optional_user_add(self, username):
        try:
            pwd.getpwnam(username)
            # Found the user, we don't need to create them
            return True
        except KeyError:
            # Return the `not` here because a 0 return indicates success and I want to
            # say something like "if adding the user is successful, return username"
            return not subprocess.call([self.create_system_user_binary, username])

    def _check_username_and_add_user(self, username):
        if self.validate_username(username) and \
                self.check_blacklist(username) and \
                self.check_whitelist(username):
            if self.create_system_users:
                if self._optional_user_add(username):
                    # Successfully added user
                    return username
                else:
                    # Failed to add user
                    self.log.error('Failed to add user by calling add user')
                    return None

            # Didn't try to add user
            return username

        # Failed to validate username or failed list check
        self.log.error('Failed to validate username or failed list check')
        return None

    def _check_role(self, user_roles):
        allowed_roles = [x.strip() for x in self.allowed_roles.split(',')]

        return any(elem in allowed_roles for elem in user_roles)

    def _valid_roles_in_assertion(self, signed_xml):
        user_roles = self._get_roles_from_saml_doc(signed_xml)

        user_roles_result = self._check_role(user_roles)
        if not user_roles_result:
            self.log.error('User role not authorized')
        return user_roles_result

    def _valid_config_and_roles(self, signed_xml):
        if self.allowed_roles and self.xpath_role_location:
            return self._valid_roles_in_assertion(signed_xml)

        if (not self.allowed_roles) and self.xpath_role_location:
            self.log.warning(self._const_warn_no_roles)
            self.log.warning(self._const_warn_explain)

        if self.allowed_roles and (not self.xpath_role_location):
            self.log.warning(self._const_warn_no_role_xpath)
            self.log.warning(self._const_warn_explain)

        # This technically skips the "neither set" case, but since that's expected-ish, I think we can let
        # that slide.
        return True

    def prepare_tornado_request(self, request, data_dict):

        https = 'off' if 'http://' in self.acs_endpoint_url else 'on'
        hostname = self.acs_endpoint_url.replace(
            'https://', '').replace('http://', '')

        result = {
            'https': https,
            'http_host': hostname,
            'server_name': hostname,
            'get_data': data_dict,
            'post_data': data_dict,
            'query_string': None
        }
        return result

    def _authenticate(self, handler, data):
        onelogin_settings = self._get_onelogin_settings(handler)

        try:
            # TODO: use OneLogin_Saml2_Auth to verify
            request_data = self.prepare_tornado_request(handler, data)
            auth = OneLogin_Saml2_Auth(
                request_data, old_settings=onelogin_settings)
            self.log.info('#### OneLogin Auth')
            self.log.info(auth)
            auth.process_response()
            errors = auth.get_errors()
            not_auth_warn = not auth.is_authenticated()

            session = {}

            if len(errors) == 0:
                session['samlUserdata'] = auth.get_attributes()
                session['samlNameId'] = auth.get_nameid()
                session['samlSessionIndex'] = auth.get_session_index()
                self_url = OneLogin_Saml2_Utils.get_self_url(request_data)
                if 'RelayState' in data and self_url != data['RelayState'][0].decode('utf-8'):
                    return handler.redirect(data['RelayState'][0].decode('utf-8'))
            elif auth.get_settings().is_debug_active():
                error_reason = auth.get_last_error_reason()

            if 'samlUserdata' in session:
                paint_logout = True
                if len(session['samlUserdata']) > 0:
                    attributes = session['samlUserdata'].items()

            self.log.info(session)
        except Exception as e:
            self.log.error('Error building tornado request')
            self.log.error(e)
            pass

        saml_response_data = data.get(self.login_post_field, None)

        # parses and validates the saml response
        saml_response = OneLogin_Saml2_Response(
            onelogin_settings, saml_response_data)
        xml = saml_response.get_xml_document()
        if xml is None or len(xml) == 0:
            self.log.error('Error getting decoded SAML Response')
            return None

        username = self._get_username_from_saml_doc(xml)
        username = self.normalize_username(username)

        https = 'off' if 'http://' in self.acs_endpoint_url else 'on'
        hostname = self.acs_endpoint_url.replace(
            'https://', '').replace('http://', '')

        try:
            request_data = {
                'servername': hostname,
                'https': https,
                'post_data': {
                    'SAMLResponse': saml_response_data
                }
            }
            saml_response_is_valid = saml_response.is_valid(
                request_data, raise_exceptions=True)
            saml_response_is_valid = self._valid_config_and_roles(xml)
        except Exception as e:
            self.log.error('Error validating SAML Response')
            self.log.error(e)
            return None

        # TODO: make is_valid work!!
        if saml_response_is_valid:
            self.log.debug('Authenticated user using SAML')

            self.log.debug(
                'Optionally create and return user: ' + username)
            return self._check_username_and_add_user(username)

        self.log.error('Error validating SAML response')
        return None

    @gen.coroutine
    def authenticate(self, handler: LoginHandler, data):
        return self._authenticate(handler, data)

    def _get_redirect_from_metadata_and_redirect(self, element_name, handler_self):
        saml_metadata_etree = self._get_saml_metadata_etree()

        handler_self.log.debug('Got metadata etree')

        if saml_metadata_etree is None or len(saml_metadata_etree) == 0:
            handler_self.log.error('Error getting SAML Metadata')
            raise web.HTTPError(500)

        handler_self.log.debug('Got valid metadata etree')

        xpath_with_namespaces = self._make_xpath_builder()

        binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        final_xpath = '//' + element_name + \
            '[@Binding=\'' + binding + '\']/@Location'
        handler_self.log.debug('Final xpath is: ' + final_xpath)

        redirect_link_getter = xpath_with_namespaces(final_xpath)

        if self.auth_version is 'v2':
            encoded_xml_content = self._make_sp_authnrequest_v2(handler_self)
        if self.auth_version is 'v1':
            xml_content = self._make_sp_authnrequest(
                handler_self, redirect_link_getter(saml_metadata_etree)[0])
            encoded_xml_content = b64encode(
                zlib.compress(xml_content.encode())[2:-4]).decode()

        # Here permanent MUST BE False - otherwise the /hub/logout GET will not be fired
        # by the user's browser.
        handler_self.redirect(redirect_link_getter(saml_metadata_etree)[0]
                              + '?SAMLRequest='
                              + parse.quote(encoded_xml_content, safe=''),
                              permanent=False)

    def _make_org_metadata(self):
        if self.organization_name or \
                self.organization_display_name or \
                self.organization_url:
            org_name_elem = org_disp_name_elem = org_url_elem = ''
            organization_name_element = '''<md:OrganizationName>{{ name }}</md:OrganizationName>'''
            organization_display_name_element = '''<md:OrganizationDisplayName>{{ displayName }}</md:OrganizationDisplayName>'''
            organization_url_element = '''<md:OrganizationURL>{{ url }}</md:OrganizationURL>'''
            organization_metadata = '''
    <md:Organization>
        {{ organizationName }}
        {{ organizationDisplayName }}
        {{ organizationUrl }}
    </md:Organization>
    '''

            if self.organization_name:
                org_name_template = Template(organization_name_element)
                org_name_elem = org_name_template.render(
                    name=self.organization_name)

            if self.organization_display_name:
                org_disp_name_template = Template(
                    organization_display_name_element)
                org_disp_name_elem = org_disp_name_template.render(
                    displayName=self.organization_display_name)

            if self.organization_url:
                org_url_template = Template(organization_url_element)
                org_url_elem = org_url_template.render(
                    url=self.organization_url)

            org_metadata_template = Template(organization_metadata)
            return org_metadata_template.render(organizationName=org_name_elem,
                                                organizationDisplayName=org_disp_name_elem,
                                                organizationUrl=org_url_elem)

        return ''

    def _make_cert_metadata(self):
        try:
            cert = self._get_preferred_cert_from_source(format=True)
        except Exception as e:
            # There was a problem getting the SAML metadata
            self.log.warning(
                'Got exception when attempting to read Certificate')
            self.log.warning('Ensure that EXACTLY ONE of cert_filepath or ' +
                             'cert_content is populated')
            self._log_exception_error(e)
            return None

        cert_data = '''<md:KeyDescriptor use="signing">
        <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>{{cert}}</ds:X509Certificate>
                </ds:X509Data>
        </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
        <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>{{cert}}</ds:X509Certificate>
                </ds:X509Data>
        </ds:KeyInfo>
    </md:KeyDescriptor>'''

        cert_metadata_template = Template(cert_data)

        return cert_metadata_template.render(cert=cert)

    def _make_sp_authnrequest_v2(self, meta_handler_self):
        authn = OneLogin_Saml2_Authn_Request(
            self._get_onelogin_settings(meta_handler_self))

        if self.use_signing:
            meta_handler_self.log.warning(authn)
            signed_request = OneLogin_Saml2_Utils.add_sign(authn.get_xml(), self._get_preferred_key_from_source(
            ), self._get_preferred_cert_from_source(), sign_algorithm=OneLogin_Saml2_Constants.SHA256, digest_algorithm=OneLogin_Saml2_Constants.SHA256)
            meta_handler_self.log.warning(signed_request)
            encoded_request = OneLogin_Saml2_Utils.deflate_and_base64_encode(
                signed_request)
            return encoded_request
        else:
            return authn.get_request()

    def _make_sp_authnrequest(self, meta_handler_self, redirect_link):

        authnrequest = '''<samlp:AuthnRequest AssertionConsumerServiceURL="{{ entityLocation }}"
    ID="{{ uuid }}" IsPassive="0" IssueInstant="{{ issue_instant }}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"
    Destination="{{ redirect_link }}" ForceAuthn="0"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml:Issuer>{{ entityId }}</saml:Issuer>
    <saml:NameIDPolicy Format="{{ nameIdFormat }}" AllowCreate="0"/>
</samlp:AuthnRequest>'''

        now = datetime.now()
        #issue_instant = now + timedelta(seconds=60)
        issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        entity_id = self.entity_id if self.entity_id else \
            meta_handler_self.request.protocol + '://' + meta_handler_self.request.host

        acs_endpoint_url = self.acs_endpoint_url if self.acs_endpoint_url else \
            entity_id + '/hub/login'

        xml_template = Template(authnrequest)
        return xml_template.render(entityId=entity_id,
                                   uuid='_' +
                                   hashlib.md5(str.encode(
                                       str(uuid.uuid4()))).hexdigest(),
                                   redirect_link=redirect_link,
                                   issue_instant=issue_instant,
                                   nameIdFormat=self.nameid_format,
                                   entityLocation=acs_endpoint_url)

    def _make_sp_metadata(self, meta_handler_self):
        metadata_text = '''<?xml version="1.0"?>
<md:EntityDescriptor
        entityID="{{ entityId }}"
        xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <md:SPSSODescriptor
            AuthnRequestsSigned="{{ signed }}"
            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>
            {{ nameIdFormat }}
        </md:NameIDFormat>
        <md:AssertionConsumerService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                Location="{{ entityLocation }}"/>
        {{ certMetadata }}
    </md:SPSSODescriptor>
    {{ organizationMetadata }}
</md:EntityDescriptor>'''

        entity_id = self.entity_id if self.entity_id else \
            meta_handler_self.request.protocol + '://' + meta_handler_self.request.host

        acs_endpoint_url = self.acs_endpoint_url if self.acs_endpoint_url else \
            entity_id + '/hub/login'

        signed = 'true' if self.use_signing else 'false'

        org_metadata_elem = self._make_org_metadata()
        cert_metadata_elem = self._make_cert_metadata()

        xml_template = Template(metadata_text)
        return xml_template.render(entityId=entity_id,
                                   nameIdFormat=self.nameid_format,
                                   entityLocation=acs_endpoint_url,
                                   organizationMetadata=org_metadata_elem,
                                   certMetadata=cert_metadata_elem,
                                   signed=signed)

    def _get_onelogin_settings(self, handler):
        entity_id = self.entity_id if self.entity_id else \
            handler.request.protocol + '://' + handler.request.host

        audience = self.audience if self.audience else \
            handler.request.protocol + '://' + handler.request.host

        acs_endpoint_url = self.acs_endpoint_url if self.acs_endpoint_url else \
            entity_id + '/hub/login'

        # TODO: what todo with logout?
        logout_url = entity_id + '/hub/logout'

        settings = OneLogin_Saml2_IdPMetadataParser.parse(
            self._get_preferred_metadata_from_source())
        settings['strict'] = False
        settings['debug'] = True
        settings['sp'] = {
            "entityId": entity_id,
            "assertionConsumerService": {
                "url": acs_endpoint_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "attributeConsumingService": {
                "serviceName": audience,
                "serviceDescription": audience,
                "requestedAttributes": [
                    {
                        "name": audience,
                        "isRequired": False,
                        "nameFormat": self.nameid_format,
                        "friendlyName": audience,
                        "attributeValue": []
                    }
                ]
            },
            "NameIDFormat": self.nameid_format,
            "x509cert": self._get_preferred_cert_from_source(format=True),
            "privateKey": self._get_preferred_key_from_source(format=True)
        }
        return OneLogin_Saml2_Settings(settings)

    def get_handlers(self, app):
        authenticator = self

        class SAMLLoginHandler(LoginHandler):

            async def get(self):
                self.log.info('Starting SP-initiated SAML Login')
                authenticator._get_redirect_from_metadata_and_redirect(
                    'md:SingleSignOnService', self)

        class SAMLLogoutHandler(LogoutHandler):
            # TODO: When the time is right to force users onto JupyterHub 1.0.0,
            # refactor this.
            async def _shutdown_servers(self, user):
                active_servers = [
                    name
                    for (name, spawner) in user.spawners.items()
                    if spawner.active and not spawner.pending
                ]
                if active_servers:
                    self.log.debug("Shutting down %s's servers", user.name)
                    futures = []
                    for server_name in active_servers:
                        futures.append(maybe_future(
                            self.stop_single_user(user, server_name)))
                    await asyncio.gather(*futures)

            def _backend_logout_cleanup(self, name):
                self.log.info("User logged out: %s", name)
                self.clear_login_cookie()
                self.statsd.incr('logout')

            async def _shutdown_servers_and_backend_cleanup(self):
                user = self.current_user
                if user:
                    await self._shutdown_servers(user)

            async def get(self):
                if authenticator.shutdown_on_logout:
                    self.log.debug('Shutting down servers during SAML Logout')
                    await self._shutdown_servers_and_backend_cleanup()

                if self.current_user:
                    self._backend_logout_cleanup(self.current_user.name)

                # This is a little janky, but there was a misspelling in a prior version
                # where someone could have set the wrong flag because of the documentation.
                # We will honor the misspelling until we rev the version, and then we will
                # break backward compatibility.
                forward_on_logout = True if authenticator.slo_forward_on_logout else False
                forwad_on_logout = True if authenticator.slo_forwad_on_logout else False
                if forward_on_logout or forwad_on_logout:
                    authenticator._get_redirect_from_metadata_and_redirect(
                        'md:SingleLogoutService', self)
                else:
                    html = self.render_template('logout.html')
                    self.finish(html)

        class SAMLMetaHandler(BaseHandler):

            async def get(self):
                xml_content = authenticator._make_sp_metadata(self)
                self.set_header('Content-Type', 'text/xml')
                self.write(xml_content)

        return [('/login', SAMLLoginHandler),
                ('/hub/login', SAMLLoginHandler),
                ('/logout', SAMLLogoutHandler),
                ('/hub/logout', SAMLLogoutHandler),
                ('/metadata', SAMLMetaHandler),
                ('/hub/metadata', SAMLMetaHandler)]
