import configparser
import os
import sys
import unittest

from collections import defaultdict
from io import StringIO
from unittest import mock

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

import snapraid_runner


class TestSum(unittest.TestCase):

    def setUp(self):
        sys.argv.extend(['-c', 'snapraid_runner.conf.example'])
        args = snapraid_runner.parse_arguments()
        snapraid_runner.load_config(args=args)


    def test_load_config(self):
        # load regular config file
        sections = ["snapraid",
                "snapraid.thresholds", "snapraid.touch", "snapraid.scrub",
                "snapraid.smart",
                "logging.console", "logging.file",
                "email", "email.smtp",
                "slack.message", "slack.attachment",
                "docker"]
        parser = configparser.RawConfigParser()
        parser.read("snapraid_runner.conf.example")
        file_config = {section: defaultdict(lambda: "") for section in sections}
        for section in parser.sections():
            for (k, v) in parser.items(section):
                file_config[section][k] = v.strip()

        bools = [
            ('snapraid', 'verbose'),
            ('snapraid.touch', 'enabled'),
            ('snapraid.scrub', 'enabled'),
            ('snapraid.smart', 'enabled'),
            ('logging.console', 'enabled'),
            ('logging.file', 'enabled'),
            ('logging.file', 'compress'),
            ('email', 'enabled'),
            ('email', 'short'),
            ('slack.message', 'enabled'),
            ('slack.attachment', 'enabled'),
            ('docker', 'enabled'),
            ('docker', 'force_resume'),
            ]
        for key, value in bools:
            file_value = file_config[key][value].lower() == "true"
            config_value = snapraid_runner.config[key][value]
            self.assertEqual(file_value, config_value)

        ints = [
            ('snapraid.thresholds', 'add'),
            ('snapraid.thresholds', 'remove'),
            ('snapraid.thresholds', 'update'),
            ('snapraid.thresholds', 'copy'),
            ('snapraid.thresholds', 'move'),
            ('snapraid.thresholds', 'restore'),
            ('snapraid.scrub', 'plan'),
            ('snapraid.scrub', 'older-than'),
            #('logging.file', 'maxsize'),
            ('logging.file', 'backups'),
            #('email', 'maxsize'),
            ('email.smtp', 'port'),
        ]
        for key, value in ints:
            file_value = int(file_config[key][value].lower())
            config_value = snapraid_runner.config[key][value]
            self.assertEqual(file_value, config_value)


if __name__ == '__main__':
    unittest.main()


