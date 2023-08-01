# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib
from ipaddress import ip_address, IPv6Address


class Node:
    def __init__(self, host, port, auth):
        try:
            if type(ip_address(host)) is IPv6Address:
                hostport = f'[{host}]:{port}'
            else:
                hostport = f'{host}:{port}'
        except ValueError:
            # host is fqdn
            hostport = f'{host}:{port}'

        self.url = f"http://{hostport}"
        self.hostname_cached = None
        self.host = host
        self.port = port
        self.auth = auth
        self.data_path_cache = None
        self.tls_port_cache = None
        self.otp_node_cached = None

    def __str__(self):
        return self.hostname()

    def __repr__(self):
        return self.__dict__.__repr__()

    def data_path(self):
        if self.data_path_cache is None:
            r = testlib.diag_eval(self, "path_config:component_path(data).")
            self.data_path_cache = r.text.strip('\"')

        return self.data_path_cache

    def addr(self, afamily=None):
        afamily_param = ''
        if afamily is not None:
            afamily_param = ', ' + ('inet6' if afamily == 'ipv6' else 'inet')
        data = f'misc:extract_node_address(node(){afamily_param}).'
        r = testlib.post_succ(self, '/diag/eval', data=data)
        return r.text.strip('"')

    def hostname(self):
        if self.hostname_cached is None:
            r = testlib.get_succ(self, '/nodes/self')
            self.hostname_cached = r.json()['hostname']
        return self.hostname_cached

    def afamily(self):
        afamily = testlib.get_succ(self, '/nodes/self').json()['addressFamily']
        assert afamily in ['inet', 'inet6'], f'unexpected afamily: {afamily}'
        return 'ipv6' if afamily == 'inet6' else 'ipv4'

    def tls_port(self):
        if self.tls_port_cache is None:
            data = 'service_ports:get_port(ssl_rest_port).'
            r = testlib.post_succ(self, '/diag/eval', data=data)
            self.tls_port_cache = int(r.text)
        return self.tls_port_cache

    def otp_port(self, encryption=None):
        encryption_param = 'cb_dist:external_encryption()'
        if encryption is not None:
            encryption_param = 'true' if encryption else 'false'
        data = '{port, P, _} = cb_epmd:get_port(' \
                                'node(), ' \
                                'cb_dist:address_family(), ' \
                                f'{encryption_param}, ' \
                                '60000),' \
               'P.'
        r = testlib.post_succ(self, '/diag/eval', data=data)
        return int(r.text)

    def otp_node(self):
        if self.otp_node_cached is None:
            r = testlib.get_succ(self, '/nodes/self')
            self.otp_node_cached = r.json()['otpNode']
        return self.otp_node_cached

    def get_ns_server_pid(self):
        r = testlib.diag_eval(self, "os:getpid().")
        return int(r.text.replace('"',""))
