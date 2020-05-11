import copy
import docker
import datetime
import json
import os
import sys
import unittest
import logging

from io import StringIO
from subprocess import CalledProcessError
from unittest import mock
from unittest.mock import MagicMock

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

import snapraid_runner

class TestSum(unittest.TestCase):

    def setUp(self):
        sys.argv.extend(['-c', 'snapraid_runner.conf.example'])
        args = snapraid_runner.parse_arguments()
        snapraid_runner.load_config(args=args)

        # preparation
        snapraid_runner.mail_log = StringIO()
        snapraid_runner.slack_log = StringIO()
        
        snapraid_runner.config['email']['enabled'] = False
        snapraid_runner.config['slack.message']['enabled'] = False
        snapraid_runner.config['slack.attachment']['enabled'] = False

        snapraid_runner.config['snapraid']['executable'] = "/usr/bin/python3"
        snapraid_runner.config['snapraid']['config'] = (
            "snapraid_runner.conf.example")
        snapraid_runner.config['snapraid.smart']['enabled'] = False
        snapraid_runner.config['snapraid.touch']['enabled'] = False
        
        snapraid_runner.config['docker']['enabled'] = False
        
        snapraid_runner.snapraid_command = mock.Mock(return_value=[])


    def test_configs_exists(self):
        # test if snapraid executable exists

        snapraid_runner.config['snapraid']['executable'] = "/bin/snapraid"

        error_msg = ("The configured SnapRAID executable "
                    f"'{snapraid_runner.config['snapraid']['executable']}'"
                    " does not exist or is not a file")
        with self.assertRaises(FileNotFoundError) as exc:
            snapraid_runner.runner()
        self.assertTrue(error_msg in str(exc.exception))

        # test if snapraid.conf exists
        snapraid_runner.config['snapraid']['executable'] = "/usr/bin/python3"
        snapraid_runner.config['snapraid']['config'] = "snapraid.conf"
        error_msg = ("The configured SnapRAID config does not exist at "
                     f"'{snapraid_runner.config['snapraid']['config']}'")
        with self.assertRaises(FileNotFoundError) as exc:
            snapraid_runner.runner()
        self.assertTrue(error_msg in str(exc.exception))


    #def test_scrub(self):
    #    snapraid_runner.config['snapraid.scrub']['enabled'] = True

    #    error_msg = "snapraid scrub"
    #    snapraid_runner.snapraid_command.side_effect = (
    #        CalledProcessError(1, error_msg))
    #    with self.assertRaises(Exception) as exc:
    #        snapraid_runner.runner()
    #    self.assertTrue(str(exc.exception.cmd) == error_msg)

    #    with self.assertRaises(SystemExit) as cm:
    #        snapraid_runner.runner()
    #    self.assertEqual(cm.exception.code, 0)


    def test_smart(self):
        snapraid_runner.config['snapraid.smart']['enabled'] = True

        snapraid_runner.config['snapraid.smart']['executable'] = "/smart"
        error_msg = ("The configured smart executable "
                     f"'{snapraid_runner.config['snapraid']['executable']}'"
                     " does not exist or is not a file")

        with self.assertRaises(FileNotFoundError) as exc:
            snapraid_runner.runner()
        self.assertTrue(error_msg in str(exc.exception))

        #error_msg = "snapraid smart"
        #snapraid_runner.snapraid_command.side_effect = (
        #    CalledProcessError(1, error_msg))
        #snapraid_runner.config['snapraid.smart']['executable'] = (
        #    "/usr/bin/python3")
        #with self.assertRaises(Exception) as exc:
        #    snapraid_runner.runner()
        #self.assertTrue(str(exc.exception.cmd) == error_msg)

        #logging.SMART = 24
        #logging.addLevelName(logging.SMART, "SMART")

        #with self.assertRaises(SystemExit) as cm:
        #    snapraid_runner.runner()
        #self.assertEqual(cm.exception.code, 0)


    def test_runner_success(self):
        with self.assertRaises(SystemExit) as cm:
            snapraid_runner.runner()
        self.assertEqual(cm.exception.code, 0)


if __name__ == '__main__':
    unittest.main()


