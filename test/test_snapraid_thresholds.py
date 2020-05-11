import copy
import datetime
import os
import sys
import unittest

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

        snapraid_runner.mail_log = StringIO()
        snapraid_runner.slack_log = StringIO()

        snapraid_runner.config['snapraid']['executable'] = "/usr/bin/python3"
        snapraid_runner.config['snapraid']['config'] = (
            "snapraid_runner.conf.example")
        
        snapraid_runner.config['docker']['enabled'] = False
        
        snapraid_runner.config['email']['enabled'] = False
        snapraid_runner.config['slack.attachment']['enabled'] = False
        snapraid_runner.config['slack.message']['enabled'] = False

        snapraid_runner.config['snapraid.smart']['enabled'] = False
        
        snapraid_runner.config['snapraid.touch']['enabled'] = False

        with open(file="test/files/snapraid.diff",
                  mode="r") as data:
            self.diff_result = data.readlines()

        # reset values
        for threshold in ['add', 'update', 'copy', 'restore', 'move', 'remove']:
            snapraid_runner.config[f'snapraid.thresholds'][threshold] = -1


    def test_snapraid_no_diff(self):
        snapraid_runner.finish = mock.Mock(return_value=None)
        snapraid_runner.snapraid_command = mock.Mock(
            return_value=self.diff_result)

        self.assertTrue(snapraid_runner.runner)


    def test_snapraid_remove_thresholds(self):
        snapraid_runner.config['snapraid.thresholds']['remove'] = 6
        self.diff_result.extend(
            [f"remove test {remove}" for remove in range(1, 8)])
        snapraid_runner.snapraid_command = mock.Mock(return_value=self.diff_result)

        self.assertRaises(ValueError, snapraid_runner.runner)


    def test_snapraid_add_thresholds(self):
        snapraid_runner.config['snapraid.thresholds']['add'] = 6
        self.diff_result.extend([f"add test {item}" for item in range(1, 8)])
        snapraid_runner.snapraid_command = mock.Mock(
            return_value=self.diff_result)

        self.assertRaises(ValueError, snapraid_runner.runner)


    def test_snapraid_update_thresholds(self):
        snapraid_runner.config['snapraid.thresholds']['update'] = 6
        self.diff_result.extend([f"update test {item}" for item in range(1, 8)])
        snapraid_runner.snapraid_command = mock.Mock(
            return_value=self.diff_result)

        self.assertRaises(ValueError, snapraid_runner.runner)


    def test_snapraid_copy_thresholds(self):
        snapraid_runner.config['snapraid.thresholds']['copy'] = 6
        self.diff_result.extend([f"copy test {item}" for item in range(1, 8)])
        snapraid_runner.snapraid_command = mock.Mock(return_value=self.diff_result)

        self.assertRaises(ValueError, snapraid_runner.runner)


    def test_snapraid_move_thresholds(self):
        snapraid_runner.config['snapraid.thresholds']['move'] = 6
        self.diff_result.extend([f"move test {item}" for item in range(1, 8)])
        snapraid_runner.snapraid_command = mock.Mock(
            return_value=self.diff_result)

        self.assertRaises(ValueError, snapraid_runner.runner)


    def test_snapraid_restore_thresholds(self):
        snapraid_runner.config['snapraid.thresholds']['restore'] = 6
        self.diff_result.extend(
            [f"restore test {item}" for item in range(1, 8)])
        snapraid_runner.snapraid_command = mock.Mock(
            return_value=self.diff_result)

        self.assertRaises(ValueError, snapraid_runner.runner)


if __name__ == '__main__':
    unittest.main()


