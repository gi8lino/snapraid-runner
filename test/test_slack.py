import datetime
import os
import sys
import unittest
from unittest import mock

from io import StringIO

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

import snapraid_runner

class TestSum(unittest.TestCase):

    def setUp(self):
        sys.argv.extend(['-c', 'snapraid_runner.conf.example'])
        args = snapraid_runner.parse_arguments()
        snapraid_runner.load_config(args=args)
        snapraid_runner.mail_log = StringIO()
        snapraid_runner.slack_log = StringIO()

        # preparation
        snapraid_runner.config['snapraid']['executable'] = "/usr/bin/python3"
        snapraid_runner.config['snapraid']['config'] = (
            "snapraid_runner.conf.example")

        snapraid_runner.config['snapraid']['start'] = datetime.datetime.now()
        snapraid_runner.config['slack.attachment']['token'] = "TEST"
        snapraid_runner.config['slack.attachment']['channels'] = "TEST"
        snapraid_runner.config['slack.message']['webhook_url'] = (
            "https://hooks.slack.com/services/TEST")


    def test_send_slack_message(self):
        with mock.patch('snapraid_runner.requests.post') as mock_request:
            mock_request.return_value.status_code = 200

            self.assertEqual(
                snapraid_runner.send_slack_message(
                    success=True,
                    runtime="2 hours, 15 minutes"
                ),
                None
            )


    def test_send_slack_attachment(self):
        with mock.patch('snapraid_runner.requests.post') as mock_request:
            mock_request.return_value.status_code = 200
            mock_request.return_value.text = '{"ok": "true"}'

            snapraid_runner.config['slack.attachment']['force'] = True
            self.assertEqual(
                snapraid_runner.send_slack_attachment(
                    success=True,
                    runtime="2 hours, 15 minutes"
                ),
                None
            )

            snapraid_runner.config['slack.attachment']['token'] = None
            self.assertRaises(ValueError,
                snapraid_runner.send_slack_attachment,
                    success=True,
                    runtime="2 hours, 15 minutes"
            )

            snapraid_runner.config['slack.attachment']['channels'] = None
            self.assertRaises(ValueError,
                snapraid_runner.send_slack_attachment,
                    success=True,
                    runtime="2 hours, 15 minutes"
            )


    def test_finish(self):
        snapraid_runner.config['email']['enabled'] = False
        snapraid_runner.config['slack.attachment']['enabled'] = False
        snapraid_runner.config['slack.message']['enabled'] = False

        with self.assertRaises(SystemExit) as cm:
            snapraid_runner.finish(is_success=True)
        self.assertEqual(cm.exception.code, 0)


if __name__ == '__main__':
    unittest.main()
