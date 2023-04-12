# @author Couchbase <info@couchbase.com>
# @copyright 2023 Couchbase, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import testlib
import base64
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from multiprocessing import Process
import time
import requests
from urllib.parse import urlparse, parse_qs, urlunparse
from saml2 import server
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.saml import AUTHN_PASSWORD
from saml2.saml import NAME_FORMAT_URI
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.metadata import create_metadata_string
from saml2.saml import NameID
from contextlib import contextmanager
import html
import re
import datetime

debug=False
scriptdir = os.path.dirname(os.path.realpath(__file__))
mock_server_port = 8119
mock_server_host = "localhost"
mock_metadata_endpoint = "/mock/metadata"
mock_sso_redirect_url = f"http://{mock_server_host}:{mock_server_port}/mock/auth"
mock_sso_post_url = f"http://{mock_server_host}:{mock_server_port}/mock/auth/post"
mock_slo_redirect_url = f"http://{mock_server_host}:{mock_server_port}/mock/logout"
mock_slo_post_url = f"http://{mock_server_host}:{mock_server_port}/mock/logout/post"
metadataFile = os.path.join(scriptdir, "idp_metadata.xml")
idp_subject_file_path = os.path.join(scriptdir, "idp.subject")
idp_test_username = "testuser"
idp_test_user_attrs = {"sn": "TestUser",
                       "givenName": "Test",
                       "uid": "testuser",
                       "email": "test@example.com",
                       "displayName": "Test"}
deflate_encoding = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"
sp_entity_id = "sp_test_entity"


class SamlTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=2)


    def setup(self, cluster):
         testlib.put_succ(cluster,
                          f'/settings/rbac/users/external/{idp_test_username}',
                          data={'roles': 'admin'})


    def teardown(self, cluster):
        testlib.ensure_deleted(
          cluster,
          f'/settings/rbac/users/external/{idp_test_username}')


    def unsolicited_authn_and_logout_test(self, cluster):
        with saml_configured(cluster) as IDP:
            identity = idp_test_user_attrs.copy()
            binding_out, destination = \
                IDP.pick_binding("assertion_consumer_service",
                                 bindings=[BINDING_HTTP_POST],
                                 entity_id=sp_entity_id)
            name_id = NameID(text=testlib.random_str(16))

            expiration = datetime.datetime.utcnow() + \
                         datetime.timedelta(minutes=1)
            expiration_iso = expiration.replace(microsecond=0).isoformat()

            response = IDP.create_authn_response(
                         identity,
                         None, # InResponseTo is missing cause it is
                               # an unsolicited response
                         destination,
                         sp_entity_id=sp_entity_id,
                         userid=idp_test_username,
                         name_id=name_id,
                         sign_assertion=True,
                         sign_response=True,
                         authn={'class_ref': AUTHN_PASSWORD},
                         session_not_on_or_after=expiration_iso)

            response_encoded = base64.b64encode(f"{response}".encode("utf-8"))

            session = requests.Session()
            headers={'Host': 'some_addr', 'ns-server-ui': 'yes'}
            r = session.post(destination,
                             data={'SAMLResponse': response_encoded},
                             headers=headers,
                             allow_redirects=False)
            assert(r.status_code == 302)

            r = session.get(cluster.nodes[0].url + '/pools/default',
                            headers=headers)
            assert(r.status_code == 200)

            binding_out, destination = \
                IDP.pick_binding("single_logout_service",
                                 bindings=[BINDING_HTTP_POST],
                                 entity_id=sp_entity_id)

            logout_id, logout_req = IDP.create_logout_request(destination,
                                                              sp_entity_id,
                                                              name_id=name_id,
                                                              sign=True)
            logout_req_enc = base64.b64encode(f"{logout_req}".encode("utf-8"))
            r = session.post(destination,
                             data={'SAMLRequest': logout_req_enc},
                             headers=headers,
                             allow_redirects=False)
            assert(r.status_code == 200)

            (redirect_url, saml_response) = \
                extract_saml_message_from_form('SAMLResponse', r.text)
            assert redirect_url == mock_slo_post_url
            IDP.parse_logout_request_response(saml_response, binding=BINDING_HTTP_POST)


    def authn_via_post_and_sigle_logout_test(self, cluster):
        with saml_configured(cluster) as IDP:
            r = testlib.get_succ(cluster, '/saml/auth',
                                 allow_redirects=False)
            (redirect_url, saml_request) = \
                extract_saml_message_from_form('SAMLRequest', r.text)
            assert redirect_url == mock_sso_post_url
            parsed = IDP.parse_authn_request(saml_request,
                                             BINDING_HTTP_POST)
            saml_request = parsed.message
            assert BINDING_HTTP_POST == saml_request.protocol_binding
            binding_out, destination = \
                IDP.pick_binding("assertion_consumer_service",
                                 bindings=[saml_request.protocol_binding],
                                 entity_id=saml_request.issuer.text,
                                 request=saml_request)

            resp_args = IDP.response_args(saml_request)
            name_id = NameID(text=testlib.random_str(16))
            identity = idp_test_user_attrs.copy()
            response = IDP.create_authn_response(
                         identity, userid=idp_test_username,
                         sign_assertion=True,
                         sign_response=True,
                         name_id=name_id,
                         **resp_args)

            response_encoded = base64.b64encode(f"{response}".encode("utf-8"))

            session = requests.Session()
            headers={'Host': 'some_addr', 'ns-server-ui': 'yes'}
            r = session.post(destination,
                             data={'SAMLResponse': response_encoded},
                             headers=headers,
                             allow_redirects=False)
            assert(r.status_code == 302)

            r = session.get(cluster.nodes[0].url + '/pools/default',
                            headers=headers)
            assert(r.status_code == 200)

            r = session.get(cluster.nodes[0].url + '/saml/deauth',
                            headers=headers,
                            allow_redirects=False)
            assert(r.status_code == 200)

            (redirect_url, saml_logout_request) = \
                extract_saml_message_from_form('SAMLRequest', r.text)
            assert redirect_url == mock_slo_post_url
            parsed_logout_req = IDP.parse_logout_request(saml_logout_request,
                                                         BINDING_HTTP_POST)
            assert parsed_logout_req.message.name_id.text == name_id.text

            r = session.get(cluster.nodes[0].url + '/pools/default',
                            headers=headers)
            assert(r.status_code == 401)
            logout_response = IDP.create_logout_response(
                                  parsed_logout_req.message,
                                  bindings=[BINDING_HTTP_POST])
            response_encoded = base64.b64encode(f"{logout_response}".encode("utf-8"))
            binding_out, destination = \
                IDP.pick_binding("single_logout_service",
                                 bindings=[BINDING_HTTP_POST],
                                 entity_id=sp_entity_id)
            r = session.post(destination,
                             data={'SAMLResponse': response_encoded},
                             headers=headers,
                             allow_redirects=False)
            assert(r.status_code == 200)


    def authn_via_redirect_and_regular_logout_test(self, cluster):
        with saml_configured(cluster, binding="redirect",
                             verify_authn_signature=False) as IDP:
            r = testlib.get_fail(cluster, '/saml/auth', 302,
                                 allow_redirects=False)
            assert 'Location' in r.headers
            location = r.headers['Location']
            assert location.startswith(mock_sso_redirect_url)
            parsedLocation = urlparse(location)
            params = parse_qs(parsedLocation.query)
            assert 'SAMLEncoding' in params
            assert [deflate_encoding] == params['SAMLEncoding']
            assert 'SAMLRequest' in params
            parsed = IDP.parse_authn_request(params['SAMLRequest'][0],
                                             BINDING_HTTP_REDIRECT)
            saml_request = parsed.message
            # We ask to always reply in POST, because REDIRECT can't be used for
            # authn responses.
            assert BINDING_HTTP_POST == saml_request.protocol_binding
            binding_out, destination = \
                IDP.pick_binding("assertion_consumer_service",
                                 bindings=[saml_request.protocol_binding],
                                 entity_id=saml_request.issuer.text,
                                 request=saml_request)

            resp_args = IDP.response_args(saml_request)

            identity = idp_test_user_attrs.copy()
            response = IDP.create_authn_response(
                         identity, userid=idp_test_username,
                         sign_assertion=True,
                         sign_response=True,
                         **resp_args)

            response_encoded = base64.b64encode(f"{response}".encode("utf-8"))

            session = requests.Session()
            headers={'Host': 'some_addr', 'ns-server-ui': 'yes'}
            r = session.get(cluster.nodes[0].url + '/pools/default',
                            headers=headers)
            assert(r.status_code == 401)
            r = session.post(destination,
                             data={'SAMLResponse': response_encoded},
                             headers=headers,
                             allow_redirects=False)
            assert(r.status_code == 302)
            r = session.get(cluster.nodes[0].url + '/pools/default',
                            headers=headers)
            assert(r.status_code == 200)
            r = session.post(cluster.nodes[0].url + '/uilogout', headers=headers)
            assert(r.status_code == 200)
            r = session.get(cluster.nodes[0].url + '/pools/default',
                            headers=headers)
            assert(r.status_code == 401)


    def session_expiration_test(self, cluster):
        with saml_configured(cluster) as IDP:
            identity = idp_test_user_attrs.copy()
            binding_out, destination = \
                IDP.pick_binding("assertion_consumer_service",
                                 bindings=[BINDING_HTTP_POST],
                                 entity_id=sp_entity_id)
            name_id = NameID(text=testlib.random_str(16))

            expiration = datetime.datetime.utcnow() - \
                         datetime.timedelta(minutes=1)
            expiration_iso = expiration.replace(microsecond=0).isoformat()

            response = IDP.create_authn_response(
                         identity,
                         None, # InResponseTo is missing cause it is
                               # an unsolicited response
                         destination,
                         sp_entity_id=sp_entity_id,
                         userid=idp_test_username,
                         name_id=name_id,
                         sign_assertion=True,
                         sign_response=True,
                         authn={'class_ref': AUTHN_PASSWORD},
                         session_not_on_or_after=expiration_iso)

            response_encoded = base64.b64encode(f"{response}".encode("utf-8"))

            session = requests.Session()
            headers={'Host': 'some_addr', 'ns-server-ui': 'yes'}
            r = session.post(destination,
                             data={'SAMLResponse': response_encoded},
                             headers=headers,
                             allow_redirects=False)
            assert(r.status_code == 302)

            r = session.get(cluster.nodes[0].url + '/pools/default',
                            headers=headers)
            assert(r.status_code == 401)


    def reuse_assertion_test(self, cluster):
        with saml_configured(cluster, recipient='false') as IDP:
            identity = idp_test_user_attrs.copy()
            binding_out, destination = \
                IDP.pick_binding("assertion_consumer_service",
                                 bindings=[BINDING_HTTP_POST],
                                 entity_id=sp_entity_id)
            name_id = NameID(text=testlib.random_str(16))

            expiration = datetime.datetime.utcnow() + \
                         datetime.timedelta(minutes=1)
            expiration_iso = expiration.replace(microsecond=0).isoformat()

            response = IDP.create_authn_response(
                         identity,
                         None, # InResponseTo is missing cause it is
                               # an unsolicited response
                         destination,
                         sp_entity_id=sp_entity_id,
                         userid=idp_test_username,
                         name_id=name_id,
                         sign_assertion=True,
                         sign_response=True,
                         authn={'class_ref': AUTHN_PASSWORD},
                         session_not_on_or_after=expiration_iso)

            response_encoded = base64.b64encode(f"{response}".encode("utf-8"))

            headers={'Host': 'some_addr', 'ns-server-ui': 'yes'}
            session1 = requests.Session()
            session2 = requests.Session()
            session3 = requests.Session()
            r = session1.post(destination,
                             data={'SAMLResponse': response_encoded},
                             headers=headers,
                             allow_redirects=False)
            assert(r.status_code == 302)

            r = session2.post(destination,
                             data={'SAMLResponse': response_encoded},
                             headers=headers,
                             allow_redirects=False)
            assert(r.status_code == 400)

            dest_parsed = urlparse(destination)
            node2_parsed = urlparse(cluster.nodes[1].url)
            dest2_parsed = dest_parsed._replace(netloc=node2_parsed.netloc)
            destination2 = urlunparse(dest2_parsed)
            r = session3.post(destination2,
                             data={'SAMLResponse': response_encoded},
                             headers=headers,
                             allow_redirects=False)
            assert(r.status_code == 400)

            r = session1.get(cluster.nodes[0].url + '/pools/default',
                            headers=headers)
            assert(r.status_code == 200)

            r = session2.get(cluster.nodes[0].url + '/pools/default',
                            headers=headers)
            assert(r.status_code == 401)

            r = session3.get(cluster.nodes[1].url + '/pools/default',
                            headers=headers)
            assert(r.status_code == 401)


@contextmanager
def saml_configured(cluster, binding='post', verify_authn_signature=True,
                    recipient='consumeURL'):
    metadata = generate_mock_metadata(verify_authn_signature, cluster)
    with open(metadataFile, 'wb') as f:
        f.write(metadata.encode("utf-8"))
    mock_server_process = Process(target=start_mock_server)
    mock_server_process.start()
    try:
        wait_mock_server(f'http://{mock_server_host}:{mock_server_port}/ping', 150)
        set_sso_options(binding, verify_authn_signature, recipient, cluster)
        IDP = server.Server(idp_config(verify_authn_signature, cluster))
        yield IDP
    finally:
        mock_server_process.terminate()
        if os.path.exists(idp_subject_file_path):
            os.remove(idp_subject_file_path)
        if os.path.exists(metadataFile):
            os.remove(metadataFile)
        testlib.delete_succ(cluster, '/saml/settings')


def generate_mock_metadata(*args):
    cfg = idp_config(*args)
    cfg['metadata'] = {} ## making sure it will not try connecting to ns_server
                         ## when server below is being created, because saml
                         ## configuration in ns_server is not created yet
    IDP = server.Server(cfg)
    valid_for = 1 # hours
    return create_metadata_string(None, config=IDP.config, valid=valid_for,
                                  sign=True)


def start_mock_server():
    mockServer = HTTPServer((mock_server_host, mock_server_port),
                            MockIDPMetadataHandler)
    mockServer.serve_forever()


def wait_mock_server(url, retry):
    while retry > 0:
      try:
          return requests.get(url)
      except requests.exceptions.ConnectionError:
          time.sleep(0.2)
          retry -= 1
    raise RuntimeError('Mock server wait failed')


class MockIDPMetadataHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == mock_metadata_endpoint:
            self.send_response(200)
            self.send_header("Content-type", "application/samlmetadata+xml")
            self.end_headers()
            with open(metadataFile, 'rb') as f:
                md = f.read()
                self.wfile.write(md)
        elif self.path == "/ping":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'pong')
        else:
            raise RuntimeError('unhandled endpoint')

    def log_message(self, format, *args):
        if debug:
            super().log_message(format, *args)
        return


def set_sso_options(binding, sign_requests, recipient, cluster):
    cert_path = os.path.join(scriptdir, "resources", "saml", "mocksp_cert.pem")
    with open(cert_path, 'r') as f:
        cert_pem = f.read()

    key_path = os.path.join(scriptdir, "resources", "saml", "mocksp_key.pem")
    with open(key_path, 'r') as f:
        key_pem = f.read()

    idpcert_fp_path = os.path.join(scriptdir, "resources", "saml",
                                   "mockidp_cert_fingerprints.pem")
    with open(idpcert_fp_path, 'r') as f:
        trusted_fps = f.read()
    metadataURL = f'http://{mock_server_host}:{mock_server_port}{mock_metadata_endpoint}'

    settings = {'enabled': 'true',
                'idpMetadataOrigin': "http",
                'idpMetadataURL': metadataURL,
                'idpSignsMetadata': True,
                'idpMetadataRefreshIntervalS': 1,
                'idpMetadataConnectAddressFamily': 'inet',
                'idpAuthnBinding': binding,
                'idpLogoutBinding': 'post',
                'usernameAttribute': 'uid',
                'spVerifyRecipient': recipient,
                'spAssertionDupeCheck': 'global',
                'spEntityId': sp_entity_id,
                'spBaseURLScheme': 'http',
                'spOrgName': 'Test Org',
                'spOrgDisplayName': 'Test Display Name',
                'spOrgURL': 'example.com',
                'spContactName': 'test contact',
                'spContactEmail': 'test@example.com',
                'spVerifyAssertionSig': True,
                'spVerifyAssertionEnvelopSig': True,
                'spCertificate': cert_pem,
                'spKey': key_pem,
                'spSignRequests': sign_requests,
                'spSignMetadata': True,
                'spTrustedFingerprints': trusted_fps,
                'spTrustedFingerprintsUsage': 'metadataInitialOnly'}

    testlib.put_succ(cluster, '/saml/settings', json=settings)


def idp_config(verify_authn_signature, cluster):
    sp_base_url = cluster.nodes[0].url
    idp_base_url = f"http://{mock_server_host}:{mock_server_port}"
    key_path = os.path.join(scriptdir, "resources", "saml",
                            "mockidp_key.pem")
    cert_path = os.path.join(scriptdir, "resources", "saml",
                             "mockidp_cert.pem")
    log_level = "DEBUG" if debug else "ERROR"
    return {"entityid": f"{idp_base_url}{mock_metadata_endpoint}",
            "description": "My IDP",
            "valid_for": 1,
            "service": {
                "idp": {
                    "name": "Mock IdP",
                    "endpoints": {
                        "single_sign_on_service": [
                            (mock_sso_redirect_url, BINDING_HTTP_REDIRECT),
                            (mock_sso_post_url, BINDING_HTTP_POST)
                        ],
                        "single_logout_service": [
                            (mock_slo_redirect_url, BINDING_HTTP_REDIRECT),
                            (mock_slo_post_url, BINDING_HTTP_POST)
                        ]
                    },
                    "policy": {
                        "default": {
                            "lifetime": {"minutes": 15},
                            "attribute_restrictions": None,
                            "name_form": NAME_FORMAT_URI
                        },
                    },
                    "subject_data": idp_subject_file_path,
                    "name_id_format": [NAMEID_FORMAT_TRANSIENT,
                                       NAMEID_FORMAT_PERSISTENT],
                    "want_authn_requests_signed": verify_authn_signature
                },
            },
            "debug": 0,
            "key_file": key_path,
            "cert_file": cert_path,
            "metadata": {
                "remote": [{"url": f"{sp_base_url}/saml/metadata"}]
            },
            "organization": {
                "display_name": "Test Org",
                "name": "Test NAME",
                "url": "http://www.example.com",
            },
            "contact_person": [
                {
                    "contact_type": "support",
                    "given_name": "Support",
                    "email_address": "support@example.com"
                },
            ],
            "logging": {
                "version": 1,
                "formatters": {
                    "simple": {
                        "format": "[%(asctime)s] [%(levelname)s] [%(name)s.%(funcName)s] %(message)s",
                    },
                },
                "handlers": {
                    "stderr": {
                        "class": "logging.StreamHandler",
                        "stream": "ext://sys.stderr",
                        "level": log_level,
                        "formatter": "simple",
                    },
                },
                "loggers": {
                    "saml2": {
                        "level": log_level
                    },
                },
                "root": {
                    "level": log_level,
                    "handlers": [
                        "stderr",
                    ],
                },
            },
        }


def extract_saml_message_from_form(msg_type, form_data):
    action_re = re.compile('action="(.+)"')
    redirect_url = html.unescape(action_re.search(form_data).group(1))
    response_re = re.compile(f'name="{msg_type}"\s+value="(.+)"')
    saml_msg = html.unescape(response_re.search(form_data).group(1))
    return (redirect_url, saml_msg)
