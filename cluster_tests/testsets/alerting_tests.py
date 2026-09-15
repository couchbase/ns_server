# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import testlib
from datetime import datetime
import os
import re
from cryptography import x509

from testlib.mock_smtp_server import start_mock_smtp_server


class AlertTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements()

    def setup(self):
        testlib.diag_eval(self.cluster, 'menelaus_web_alerts_srv:reset().')
        limits = testlib.get_succ(self.cluster, '/settings/alerts/limits')\
            .json()
        self.prev_cert_expiration = limits['certExpirationDays']

        # Set alert check interval to 1s
        testlib.diag_eval(self.cluster,
                          'ns_config:set({timeout,{menelaus_web_alerts_srv,'
                          'sample_rate}}, 1000)')
        testlib.diag_eval(self.cluster,
                          'menelaus_web_alerts_srv ! check_alerts')

        # Set up mock SMTP server for email verification
        self.mock_smtp_server = self.setup_mock_email_server(
            smtp_host='127.0.0.1',
            smtp_port=None,  # auto-assign port
            sender='alerts_test@example.com',
            recipients='admin@example.com',
            enable_alerts=None  # preserve existing/default alerts
        )

    def teardown(self):
        # Stop mock SMTP server and restore email configuration
        self.teardown_mock_email_server()

        testlib.diag_eval(self.cluster, 'menelaus_web_alerts_srv:reset().')
        testlib.post_succ(self.cluster, '/settings/alerts/limits',
                          data={'certExpirationDays':
                                str(self.prev_cert_expiration)})

        # Set alert check interval back to default 60s
        testlib.diag_eval(self.cluster,
                          'ns_config:delete({timeout,{menelaus_web_alerts_srv,'
                          'sample_rate}})')

    def test_teardown(self):
        # Clear captured emails after each test to ensure clean state for next
        # test
        if hasattr(self, 'mock_smtp_server') and self.mock_smtp_server:
            try:
                self.mock_smtp_server.clear_emails()
            except Exception:
                pass

    def setup_mock_email_server(self, smtp_host='127.0.0.1', smtp_port=None,
                                sender='test_sender@example.com',
                                recipients='test_recipient@example.com',
                                enable_alerts=None, use_tls=False):
        """
        Set up a mock SMTP server and configure the cluster to use it for
        email alerts.

        Args:
            smtp_host: Host for the mock SMTP server (default: 127.0.0.1)
            smtp_port: Port for the mock SMTP server (None for auto-assign)
            sender: Email sender address (default: test_sender@example.com)
            recipients: Comma-separated list of email recipients
            enable_alerts: List of alert types to enable for email (None to
                           preserve existing)
            use_tls: Whether to use TLS for SMTP (STARTTLS)

        Returns:
            SMTPServerRunner instance
        """
        # Log next to the node's data, as there is no cluster-wide log dir
        node_data_dir = self.cluster.connected_nodes[0].data_path()
        self.smtp_log_path = os.path.join(node_data_dir, 'mock_smtp.log')
        print(f"SMTP server log will be written to: {self.smtp_log_path}")

        # Start mock SMTP server
        self.mock_smtp_server = start_mock_smtp_server(
                                  host=smtp_host,
                                  port=smtp_port or 0,
                                  use_tls=use_tls,
                                  log_file_path=self.smtp_log_path)
        actual_port = self.mock_smtp_server.port

        # Configure cluster email settings
        self.configure_email_alerts(
            enabled=True,
            sender=sender,
            recipients=recipients,
            smtp_host=smtp_host,
            smtp_port=actual_port,
            smtp_encrypt=use_tls,
            enable_alerts=enable_alerts
        )

        return self.mock_smtp_server

    def teardown_mock_email_server(self):
        """Stop the mock SMTP server and restore original email
        configuration."""
        if hasattr(self, 'mock_smtp_server') and self.mock_smtp_server:
            try:
                self.mock_smtp_server.clear_emails()
            except:
                pass
            try:
                self.mock_smtp_server.stop_server()
            except:
                pass
            self.mock_smtp_server = None

        # Disable email alerts to restore default state
        self.configure_email_alerts(enabled=False)

    def configure_email_alerts(self, enabled=False,
                               sender='couchbase@localhost',
                               recipients='root@localhost',
                               smtp_host='localhost',
                               smtp_port=25,
                               smtp_user='',
                               smtp_pass='',
                               smtp_encrypt=False,
                               enable_alerts=None):
        """
        Configure email alert settings on the cluster.

        Args:
            enabled: Whether email alerts are enabled
            sender: Email sender address
            recipients: Comma-separated list of email recipients
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            smtp_user: SMTP username
            smtp_pass: SMTP password
            smtp_encrypt: Whether to use TLS/SSL for SMTP
            enable_alerts: List of alert types to enable (None to preserve
                           existing)
        """
        # Get current alert configuration to preserve existing alerts when
        # not specified
        if enable_alerts is None:
            r = testlib.get_succ(self.cluster, '/settings/alerts')
            current_settings = r.json()
            enable_alerts = current_settings.get('alerts', [])
            print(f"Preserving {len(enable_alerts)} existing alert types")

        email_data = {
            'enabled': 'true' if enabled else 'false',
            'sender': sender,
            'recipients': recipients,
            'emailHost': smtp_host,
            'emailPort': str(smtp_port),
            'emailUser': smtp_user,
            'emailPass': smtp_pass,
            'emailEncrypt': 'true' if smtp_encrypt else 'false'
        }

        # Add alerts parameter if we have alerts to enable
        if enable_alerts is not None and enable_alerts != []:
            email_data['alerts'] = ','.join(alert for alert in enable_alerts)

        print(f"Configuring email alerts: {email_data}")
        testlib.post_succ(self.cluster, '/settings/alerts', data=email_data)

        # Verify the settings were applied
        response = testlib.get_succ(self.cluster, '/settings/alerts').json()
        assert response['enabled'] == enabled, \
            "Email alerts not configured correctly"
        print(f"Email alerts configured: enabled={enabled}, "
              f"alerts={len(response.get('alerts', []))}, "
              f"sender={response['sender']}, "
              f"recipients={response['recipients']}")

    def cert_about_to_expire_alert_test(self):
        node_data_dir = self.cluster.connected_nodes[0].data_path()
        certs_dir = os.path.join(node_data_dir, 'config', 'certs')
        cert_path = os.path.join(certs_dir, 'chain.pem')
        client_cert_path = os.path.join(certs_dir, 'client_chain.pem')
        expiration1 = get_expiration_for_cert(cert_path)
        expiration2 = get_expiration_for_cert(client_cert_path)
        max_expiration = max(expiration1, expiration2)

        testlib.post_succ(self.cluster, '/settings/alerts/limits',
                          data={'certExpirationDays': str(max_expiration)})

        def check_alert():
            r = testlib.get_succ(self.cluster, '/pools/default').json()
            alerts = r['alerts']
            if len(alerts) < 2:
                print(f"Alert check failed, expected >= 2 alerts, got {alerts}")
                return False

            regex = r'^Server certificate for node .+ will expire at .+$'

            def is_expected(x): return re.match(regex, x['msg']) is not None
            has_node_alert = any(map(is_expected, alerts))

            if not has_node_alert:
                print(f"Alert check failed, expected {regex}, got {alerts}")
                return False

            regex = r'^Client certificate on node .+ will expire at .+$'

            def is_expected(x): return re.match(regex, x['msg']) is not None
            has_client_alert = any(map(is_expected, alerts))

            if not has_client_alert:
                print(f"Alert check failed, expected {regex}, got {alerts}")
                return False

            return True

        testlib.poll_for_condition(check_alert, sleep_time=1, timeout=120,
                                   verbose=True,
                                   msg='wait for cert expiration alert')


def get_expiration_for_cert(cert_path):
    print(f'Extracting expiration for {cert_path}')
    with open(cert_path, 'rb') as f:
        pem = f.read()
    cert = x509.load_pem_x509_certificate(pem)
    expire_datetime = cert.not_valid_after
    print(f'expire_datetime: {expire_datetime}')
    now_datetime = datetime.utcnow()
    print(f'now: {now_datetime}')
    assert expire_datetime > now_datetime
    will_expire_in = (expire_datetime - now_datetime).days + 1
    print(f'cert will expire in {will_expire_in} days')
    return will_expire_in
