# snapraid_runner
import argparse
import configparser
import copy
import datetime
import gzip
import json
import logging
import logging.handlers
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
import traceback
from collections import Counter, defaultdict, namedtuple
from io import StringIO

try:
    import requests
except ImportError:
    sys.stderr.write(f"{traceback.format_exc()}\n")
    raise ImportError(
        "Please install all dependencies (pip install -r requirements.txt)")

__version__ = "v1.0.0"
__author__ = "gi8lino (2020)"

# global variables
config = None
mail_log, slack_log = None, None
slack_filesUpload = "https://slack.com/api/files.upload"
slack_webhook_url = "https://hooks.slack.com/services"

Pattern = namedtuple("Pattern", [
    "progressbar",
    "diff_result"
    ]
)
pattern = Pattern(
    # progressbar
    re.compile(
        pattern=r"(\d{1,2}%,\s+\d+\s+MB)",
        flags=re.IGNORECASE),
    # diff_result
    re.compile(
        pattern=r"(\d+)\s+(equal|added|removed|updated|moved|copied|restored)",
        flags=re.IGNORECASE),
)


def parse_arguments():
    parser = argparse.ArgumentParser(
        formatter_class=(
            lambda prog: argparse.HelpFormatter(prog, max_help_position=26)),
        description="""
This Script runs SnapRAID and sends it output to the console, a log file,
via eMail and/or Slack.
It runs 'diff' before 'sync' to see how many files were deleted, updated,
copied, moved or restored and aborts if that number exceeds the set threshold.
It can run 'touch' before and 'scrub' after 'sync'.
If configured, it also runs 'smart'.
All this is configurable in the config file or by overriding with
start arguments.""",
        epilog="""
created by https://github.com/gi8lino/snapraid-runner
inspired by https://github.com/Chronial/snapraid-runner
"""
)

    parser.add_argument("-v", "--version",
                        action="version",
                        version=f"snapraid_runner version "
                                f"{__version__}\nby {__author__}")
    parser.add_argument("--log-config",
                        action="store_true",
                        dest="log_config",
                        help="log used config. "
                             "(confidential config entries like Password or "
                             "eMail will be pruned)")
    parser.add_argument("-c",
                        default="snapraid_runner.conf",
                        dest="conf",
                        metavar="PATH",
                        help="path to configuration file "
                             "(default: %(default)s)")
    group = parser.add_argument_group('arguments to override config')
    group_verbose = group.add_mutually_exclusive_group(required=False)
    group_verbose.add_argument("--verbose",
                               action="store_true",
                               default=None,
                               dest="verbose",
                               help="set SnapRAID output to verbose")
    group_verbose.add_argument("--no-verbose",
                               action="store_true",
                               default=None,
                               dest="verbose",
                               help="do not set SnapRAID output to verbose")
    group.add_argument("--no-addthreshold",
                       action="store_true",
                       default=None,
                       dest="disable_add_threshold",
                       help="do not use add threshold")
    group.add_argument("--no-removethreshold",
                       action="store_true",
                       default=None,
                       dest="disable_remove_threshold",
                       help="do not use delete threshold")
    group.add_argument("--no-updatethreshold",
                       action="store_true",
                       default=None,
                       dest="disable_update_threshold",
                       help="do not use update threshold")
    group.add_argument("--no-copythreshold",
                       action="store_true",
                       default=None,
                       dest="disable_copy_threshold",
                       help="do not use copy threshold")
    group.add_argument("--no-movethreshold",
                       action="store_true",
                       default=None,
                       dest="disable_move_threshold",
                       help="do not use move threshold")
    group.add_argument("--no-restorethreshold",
                       action="store_true",
                       default=None,
                       dest="disable_restore_threshold",
                       help="do not use restore threshold")
    group_touch = group.add_mutually_exclusive_group(required=False)
    group_touch.add_argument("--touch",
                             action="store_true",
                             default=None,
                             dest="touch",
                             help="run touch before sync")
    group_touch.add_argument("--no-touch",
                             action="store_false",
                             default=None,
                             dest="touch",
                             help="do not run touch")
    group_scrub = group.add_mutually_exclusive_group(required=False)
    group_scrub.add_argument("--scrub",
                             action="store_true",
                             default=None,
                             dest="scrub",
                             help="run scrub after sync")
    group_scrub.add_argument("--no-scrub",
                             action="store_false",
                             default=None,
                             dest="scrub",
                             help="do not run scrub")
    group_smart = group.add_mutually_exclusive_group(required=False)
    group_smart.add_argument("--smart",
                             action="store_true",
                             default=None,
                             dest="smart",
                             help="run smart after sync")
    group_smart.add_argument("--no-smart",
                             action="store_false",
                             default=None,
                             dest="smart",
                             help="do not run smart")
    group_mail = group.add_mutually_exclusive_group(required=False)
    group_mail.add_argument("--mail",
                            action="store_true",
                            default=None,
                            dest="mail",
                            help="send an eMail")
    group_mail.add_argument("--no-mail",
                            action="store_false",
                            default=None,
                            dest="mail",
                            help="do not send an eMail")
    group_mail.add_argument("--force-mail",
                            action="store_true",
                            default=None,
                            dest="force_mail",
                            help="ignore 'sendon' and send always an eMail")
    group_short_mail = group.add_mutually_exclusive_group(required=False)
    group_short_mail.add_argument("--short-mail",
                                  action="store_true",
                                  default=None,
                                  dest="short_mail",
                                  help="do not send full SnapRAID output "
                                       "as eMail")
    group_short_mail.add_argument("--long-mail",
                                  action="store_false",
                                  default=None,
                                  dest="short_mail",
                                  help="send full SnapRAID output as eMail")
    group_message = group.add_mutually_exclusive_group(required=False)
    group_message.add_argument("--message",
                               action="store_true",
                               default=None,
                               dest="slack_message",
                               help="send a Slack message")
    group_message.add_argument("--no-message",
                               action="store_false",
                               default=None,
                               dest="slack_message",
                               help="do not send a Slack message")
    group_message.add_argument("--force-message",
                               action="store_true",
                               default=None,
                               dest="force_message",
                               help="ignore 'sendon' and send always a "
                                    "Slack message")
    group_attachment = group.add_mutually_exclusive_group(required=False)
    group_attachment.add_argument("--attachment",
                                  action="store_true",
                                  default=None,
                                  dest="slack_attachment",
                                  help="send a Slack attachment")
    group_attachment.add_argument("--no-attachment",
                                  action="store_false",
                                  default=None,
                                  dest="slack_attachment",
                                  help="do not send a Slack attachment")
    group_attachment.add_argument("--force-attachment",
                                  action="store_true",
                                  default=None,
                                  dest="force_attachment",
                                  help="ignore 'sendon' and send always a "
                                       "Slack attachment")
    group_short_attach = group.add_mutually_exclusive_group(required=False)
    group_short_attach.add_argument("--short-attachment",
                                    action="store_true",
                                    default=None,
                                    dest="short_attachment",
                                    help="do not send full SnapRAID output "
                                         "as Slack attachment")
    group_short_attach.add_argument("--long-attachment",
                                    action="store_false",
                                    default=None,
                                    dest="short_attachment",
                                    help="send full SnapRAID output "
                                         "as Slack attachment")

    args, unknown = parser.parse_known_args()
    if unknown:
        sys.stderr.write("skip unknown arg{}: '{}'\n".format(
            "s" if len(unknown) != 1 else "",
            "', '".join(unknown)))
    return args


def load_config(args):
    """load config file"""
    global config
    if not os.path.exists(args.conf):
        raise FileNotFoundError("snapraid_runner configuration file not found")

    parser = configparser.RawConfigParser()
    parser.read(args.conf)
    sections = ["snapraid",
                "snapraid.thresholds", "snapraid.touch", "snapraid.scrub",
                "snapraid.smart",
                "logging.console", "logging.file",
                "email", "email.smtp",
                "slack.message", "slack.attachment"]
    config = {section: defaultdict(lambda: "") for section in sections}
    for section in parser.sections():
        for (k, v) in parser.items(section):
            config[section][k] = v.strip()

    config['snapraid']['verbose'] = (
        args.verbose if args.verbose is not None
        else config['snapraid']['verbose'].lower() == "true")

    config['snapraid.thresholds']['add'] = (
        -1 if args.disable_add_threshold or
           not config['snapraid.thresholds'].get('add')
           else (
            int(config['snapraid.thresholds']['add']) if
            config['snapraid.thresholds']['add'].lstrip("-").isdigit() else
            0))

    config['snapraid.thresholds']['remove'] = (
        -1 if args.disable_remove_threshold else (
            int(config['snapraid.thresholds']['remove']) if
            config['snapraid.thresholds']['remove'].lstrip("-").isdigit() else
            0))
    config['snapraid.thresholds']['update'] = (
        -1 if args.disable_update_threshold else (
            int(config['snapraid.thresholds']['update']) if
            config['snapraid.thresholds']['update'].lstrip("-").isdigit() else
            0))
    config['snapraid.thresholds']['copy'] = (
        -1 if args.disable_copy_threshold else (
            int(config['snapraid.thresholds']['copy']) if
            config['snapraid.thresholds']['copy'].lstrip("-").isdigit() else
            0))
    config['snapraid.thresholds']['move'] = (
        -1 if args.disable_move_threshold else (
            int(config['snapraid.thresholds']['move']) if
            config['snapraid.thresholds']['move'].lstrip("-").isdigit() else
            0))
    config['snapraid.thresholds']['restore'] = (
        -1 if args.disable_restore_threshold else (
            int(config['snapraid.thresholds']['restore']) if
            config['snapraid.thresholds']['restore'].lstrip("-").isdigit() else
            0))

    config['snapraid.touch']['enabled'] = (
        args.touch if args.touch is not None else
        config['snapraid.touch']['enabled'].lower() == "true")

    config['snapraid.scrub']['enabled'] = (
        args.scrub if args.scrub is not None else
        config['snapraid.scrub']['enabled'].lower() == "true")
    config['snapraid.scrub']['plan'] = (
        int(config['snapraid.scrub']['plan']) if
        config['snapraid.scrub']['plan'].isdigit() else 0)
    config['snapraid.scrub']['older-than'] = (
        int(config['snapraid.scrub']['older-than']) if
        config['snapraid.scrub']['older-than'].isdigit() else 0)

    config['snapraid.smart']['enabled'] = (
        args.smart if args.smart is not None else
        config['snapraid.smart']['enabled'].lower() == "true")

    config['logging.file']['enabled'] = (
        config['logging.file']['enabled'].lower() == "true")
    config['logging.file']['path'] = (
        os.path.abspath(config['logging.file']['path']) if
        config['logging.file']['path'] else None)
    config['logging.file']['json'] = (
        config['logging.file']['json'].lower() == "true")
    config['logging.file']['maxsize'] = (
        int(config['logging.file']['maxsize']) if
        config['logging.file']['maxsize'].isdigit() else 0)
    config['logging.file']['backups'] = (
        int(config['logging.file']['backups']) if
        config['logging.file']['backups'].isdigit() else 0)
    config['logging.file']['compress'] = (
        config['logging.file']['compress'].lower() == "true")

    config['logging.console']['enabled'] = (
        config['logging.console']['enabled'].lower() == "true")
    config['logging.console']['json'] = (
        config['logging.console']['json'].lower() == "true")

    config['email']['enabled'] = (
        args.mail if args.mail is not None else
        config['email']['enabled'].lower() == "true")
    config['email']['force'] = args.force_mail
    config['email']['short'] = (
        args.short_mail if args.short_mail is not None else
        config['email']['short'].lower() == "true")
    config['email']['maxsize'] = (
        int(config['email']['maxsize']) if
        config['email']['maxsize'].isdigit() else 0)

    config['email.smtp']['port'] = (
        int(config['email.smtp']['port']) if
        config['email.smtp']['port'].isdigit() else None)
    config['email.smtp']['ssl'] = (
        True if config['email.smtp']['encryption'].lower() == "ssl" else False)
    config['email.smtp']['tls'] = (
        True if config['email.smtp']['encryption'].lower() == "tls" else False)

    config['slack.message']['enabled'] = (
        args.slack_message if args.slack_message is not None else
        config['slack.message']['enabled'].lower() == "true")
    config['slack.message']['force'] = args.force_message

    config['slack.attachment']['enabled'] = (
        args.slack_attachment if args.slack_attachment is not None else
        config['slack.attachment']['enabled'].lower() == "true")
    config['slack.attachment']['force'] = args.force_attachment
    config['slack.attachment']['short'] = (
        args.short_attachment if args.short_attachment is not None else
        config['slack.attachment']['short'].lower() == "true")


def setup_logger():
    """setup console, file, email and/or slack logger"""
    def rotator(source, dest):
        with open(source, 'rb') as f_in:
            with gzip.open(dest, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(source)

    logging.getLogger("urllib3").setLevel(logging.WARNING)

    json_format = logging.Formatter(
        '{"time": "%(asctime)s",'
        '"level": "%(levelname)s",'
        '"message": "%(message)s"}')
    default_format = logging.Formatter(
        "%(asctime)s [%(levelname)-7.7s] %(message)s")

    root_logger = logging.getLogger()
    logging.OUTPUT = 15
    logging.addLevelName(logging.OUTPUT, "OUTPUT")
    # we only run smart for its output, so we always include it
    logging.SMART = 24
    logging.addLevelName(logging.SMART, "SMART")
    logging.OUTERR = 25
    logging.addLevelName(logging.OUTERR, "OUTERR")
    root_logger.setLevel(logging.OUTPUT)

    if config['logging.console']['enabled']:
        console_logger = logging.StreamHandler(sys.stdout)
        console_logger.setFormatter(
            json_format if config['logging.console']['json'] else
            default_format)
        root_logger.addHandler(console_logger)

    if config['logging.file']['enabled'] and config['logging.file']['path']:
        file_logger = logging.handlers.RotatingFileHandler(
            config['logging.file']['path'],
            maxBytes=(config['logging.file']['maxsize'] * 1024),
            backupCount=config['logging.file']['backups'],
            encoding="utf-8")
        file_logger.setFormatter(
            json_format if config['logging.file']['json'] else
            default_format)
        if config['logging.file']['compress']:
            file_logger.rotator = rotator
            file_logger.namer = lambda n: n + ".gz"
        root_logger.addHandler(file_logger)

    if config['email']['enabled'] or config['email']['force']:
        global mail_log
        mail_log = StringIO()
        mail_logger = logging.StreamHandler(mail_log)
        mail_logger.setFormatter(default_format)
        if config['email']['short']:
            # don't send program stdout in email
            mail_logger.setLevel(logging.INFO)
        root_logger.addHandler(mail_logger)

    if (config['slack.attachment']['enabled'] or
       config['slack.attachment']['force']):
            global slack_log
            slack_log = StringIO()
            slack_logger = logging.StreamHandler(slack_log)
            slack_logger.setFormatter(default_format)
            if config['slack.attachment']['short']:
                # don't send program stdout in slack attachment
                slack_logger.setLevel(logging.INFO)
            root_logger.addHandler(slack_logger)


def log_config():
    def hide_mail(mail):
        if "@" not in mail:
            return "*" * 10
        mail = mail.split("@")
        return "%s%s%s@%s" % (
            mail[0][:2],
            "*" * (len(mail[0]) - 4),
            mail[0][-2:],
            mail[1])

    # hide passwords
    logging.info("start arguments: %s", sys.argv)
    secret_config = copy.deepcopy(config)
    secret_config['email']['from'] = hide_mail(
        secret_config['email']['from'])
    secret_config['email']['to'] = hide_mail(
        secret_config['email']['to'])
    secret_config['email.smtp']['user'] = hide_mail(
        secret_config['email.smtp']['user'])
    secret_config['email.smtp']['password'] = "*" * 10
    secret_config['slack.message']['webhook_url'] = "%s%s" % (
        secret_config['slack.message']['webhook_url'][:35],
        "*" * 10)
    secret_config['slack.attachment']['token'] = "%s%s%s" % (
        secret_config['slack.attachment']['token'][:2],
        "*" * 10,
        secret_config['slack.attachment']['token'][-2:])
    secret_config['slack.attachment']['channels'] = "%s%s%s" % (
        secret_config['slack.attachment']['channels'][:2],
        "*" * 5,
        secret_config['slack.attachment']['channels'][-2:])
    logging.info("loaded config: %s", json.dumps(secret_config))


def runner():
    config['snapraid']['start'] = datetime.datetime.now()
    logging.info("=" * 50)
    logging.info("Run started")
    logging.info("=" * 50)

    if not os.path.isfile(config['snapraid']['executable']):
        raise FileNotFoundError("The configured SnapRAID executable"
                                f" '{config['snapraid']['executable']}' "
                                "does not exist or is not a file")
    if not os.path.isfile(config['snapraid']['config']):
        raise FileNotFoundError("The configured SnapRAID config does not "
                                f"exist at '{config['snapraid']['config']}'")

    if config['snapraid.touch']['enabled']:
        logging.info("Running touch...")
        snapraid_command(command="touch")
        logging.info("*" * 50)

    logging.info("Running diff...")
    actions = [
        "equal",
        "add",
        "remove",
        "update",
        "move",
        "copy",
        "restore"
    ]
    # If a "sync" is required, the process return code is 2, instead of the
    # default 0. The return code 1 is instead for a generic error condition.
    diff_out = snapraid_command(command="diff", allow_statuscodes=[2])
    diff_result = Counter(line.split()[0] for line in diff_out if
                          line.split()[0] in actions)
    diff_result = {action: diff_result[action] for action in actions}
    logging.info(("Diff results: "
                  "{equal} equal, "
                  "{add} added, "
                  "{remove} removed, "
                  "{update} updated, "
                  "{move} moved, "
                  "{copy} copied, "
                  "{restore} restored"
                  ).format(**diff_result))
    logging.info("*" * 50)

    if (config['snapraid.thresholds']['add'] >= 0 and
        diff_result['add'] >
            config['snapraid.thresholds']['add']):
                raise ValueError("Added files exceed add threshold of "
                                 f"{config['snapraid.thresholds']['add']}"
                                 ", aborting")

    if (config['snapraid.thresholds']['remove'] >= 0 and
        diff_result['remove'] >
            config['snapraid.thresholds']['remove']):
                raise ValueError("Removed files exceed remove threshold of "
                                 f"{config['snapraid.thresholds']['remove']}"
                                 ", aborting")

    if (config['snapraid.thresholds']['update'] >= 0 and
        diff_result['update'] >
            config['snapraid.thresholds']['update']):
                raise ValueError("Updated files exceed update threshold of "
                                 f"{config['snapraid.thresholds']['update']}"
                                 ", aborting")

    if (config['snapraid.thresholds']['copy'] >= 0 and
        diff_result['copy'] > config['snapraid.thresholds']['copy']):
                raise ValueError("Copied files exceed copy threshold of "
                                 f"{config['snapraid.thresholds']['copy']}"
                                 ", aborting")

    if (config['snapraid.thresholds']['move'] >= 0 and
        diff_result['move'] > config['snapraid.thresholds']['move']):
                raise ValueError("Moved files exceed update threshold of "
                                 f"{config['snapraid.thresholds']['move']}"
                                 ", aborting")

    if (config['snapraid.thresholds']['restore'] >= 0 and
        diff_result['restore'] >
            config['snapraid.thresholds']['restore']):
                raise ValueError("Restored files exceed restore threshold of "
                                 f"{config['snapraid.thresholds']['restore']}"
                                 ", aborting")

    if sum(diff_result.values()) == 0:
        logging.info("No changes detected, no sync required")
    else:
        logging.info("Running sync...")
        snapraid_command(command="sync")
        logging.info("*" * 50)

    if config['snapraid.scrub']['enabled']:
        logging.info("Running scrub (%s%s, %s days)...",
                     config['snapraid.scrub']['plan'], "%",
                     config['snapraid.scrub']['older-than'])
        snapraid_command(command="scrub", args={
            "plan": config['snapraid.scrub']['plan'],
            "older-than": config['snapraid.scrub']['older-than'],
        })
        logging.info("*" * 50)

    if config['snapraid.smart']['enabled']:
        if not os.path.exists(config['snapraid.smart']['executable']):
            raise FileNotFoundError("The configured smart executable"
                                    f" '{config['snapraid']['executable']}' "
                                    "does not exist or is not a file")
        logging.info("Running smart...")
        snapraid_command(command="smart", output_log_level=logging.SMART)
        logging.info("*" * 50)

    logging.info("All done")
    logging.info("*" * 50)
    finish(True)


def snapraid_command(command,
                     args={},
                     allow_statuscodes=[],
                     output_log_level=None):
    """Run snapraid command

    Arguments:
        command {string} -- snapraid command

    Keyword Arguments:
        args {dict} -- snapraid command arguments (default: {None})
        allow_statuscodes {list} -- list of special return codes for errors
                              (default: 1)
                              snapraid diff return codes:
                              0 - Nothing to do
                              1 - Generic error
                              2 - Sync required
        output_log_level {logging.LOGLEVEL} -- special log level for stdout.
                                               if not set it take OUTPUT

    Raises:
        subprocess.CalledProcessError: snapraid error

    Returns:
        [list] -- list with output
    """
    arguments = ['--conf', config['snapraid']['config']]
    if config['snapraid']['verbose']:
        arguments.extend(['--verbose'])
    for (k, v) in args.items():
        arguments.extend([f"--{k}", str(v)])
    p = subprocess.Popen(
        [config['snapraid']['executable'], command] + arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf8"
        )
    out = []
    threads = [
        _tee_log(std=p.stdout,
                 out_lines=out,
                 log_level=output_log_level or logging.OUTPUT),
        _tee_log(std=p.stderr,
                 out_lines=[],
                 log_level=logging.OUTERR)]
    for t in threads:
        t.join()
    ret = p.wait()
    time.sleep(0.3)  # sleep for a while to make pervent output mixup
    if ret != 0 and ret not in allow_statuscodes:
        raise subprocess.CalledProcessError(ret, "snapraid " + command)

    return out


def _tee_log(std, out_lines, log_level):
    """Create a thread that saves all the output on std to out_lines and
    logs every line with log_level

    Arguments:
        std {IORedirector} -- stdout or stderr
        out_lines {list} -- set output to list
        log_level {logging.LEVEL} -- output log level

    Returns:
        thread -- thread who log program output
    """

    def tee_thread():
        for line in iter(std.readline, ""):
            line = line.strip()
            if not line:  # skip empty line
                continue
            # do not log the progress display
            if pattern.progressbar.match(string=line):
                continue
            # do not log diff result
            if pattern.diff_result.match(string=line):
                continue
            logging.log(log_level, line)
            out_lines.append(line)
        std.close()
    t = threading.Thread(target=tee_thread)
    t.daemon = True
    t.start()
    return t


def finish(is_success):
    """write summary and send mail and/or slack notification

    Arguments:
        success {bool} -- processing was successful
    """
    def calculate_runtime(start_time):
        seconds = (
            datetime.datetime.now() - config['snapraid']['start']).seconds
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        days, hours = divmod(hours, 24)
        periods = [
            ('day', days),
            ('hour', hours),
            ('minute', minutes),
            ('second', seconds),
        ]
        return (', '.join(
            f"{value} {name}{'s' if value != 1 else ''}" for name, value in
            periods if value))

    time_string = calculate_runtime(config['snapraid']['start'])

    send_notification = False
    if (config['email']['enabled'] and
        ("error", "success")[is_success] in config['email']['sendon']) or (
            config['email']['force']):
                try:
                    logging.info("Send notifications...")
                    send_notification = True
                    send_email(success=is_success, runtime=time_string)
                    logging.info("successfully send eMail")
                except Exception as e:
                    logging.exception("Failed to send eMail. %s", e)

    if (config['slack.message']['enabled'] and
        ("error", "success")[is_success] in
        config['slack.message']['sendon']) or (
            config['slack.message']['force']):
                try:
                    if not send_notification:
                        logging.info("Send notifications...")
                    send_notification = True
                    send_slack_message(success=is_success,
                                       runtime=time_string)
                    logging.info("successfully send Slack message")
                except Exception as e:
                    logging.exception("Failed to send Slack message. %s", e)

    if (config['slack.attachment']['enabled'] and
        ("error", "success")[is_success] in
        config['slack.attachment']['sendon']) or (
            config['slack.attachment']['force']):
                try:
                    if not send_notification:
                        logging.info("Send notifications...")
                    send_notification = True
                    send_slack_attachment(success=is_success,
                                          runtime=time_string)
                    logging.info("successfully send Slack attachment")
                except Exception as e:
                    logging.exception("Failed to send Slack attachment. %s", e)
    if send_notification:
        logging.info("*" * 50)

    if is_success:
        logging.info("Run finished successfully")
    else:
        logging.error("Run failed")

    sys.exit(0 if is_success else 1)


def send_email(success, runtime):
    """send email notification

    Arguments:
        success {bool} -- processing was successful
        runtime {sting} -- script runtime
    """
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email import charset
    except ImportError as e:
        raise ImportError(f"Cannot import {e}")

    if not config['email.smtp']['host']:
        raise ValueError("Failed to send eMail because smtp Host is not set")

    if not config['email']['from']:
        raise ValueError("Failed to send eMail because 'from' is not set")

    if not config['email']['to']:
        raise ValueError("Failed to send eMail because 'to' is not set")

    # use quoted-printable instead of the default base64
    charset.add_charset("utf-8", charset.SHORTEST, charset.QP)

    body = f"snapraid_runner finished in {runtime}.\n\n"

    if success:
        body += "SnapRAID job completed successfully:\n\n\n"
    else:
        body += "Error during SnapRAID job:\n\n\n"

    if mail_log:
        log = mail_log.getvalue()

        maxsize = config['email']['maxsize'] * 1024
        if maxsize and len(log) > maxsize:
            log = (
                "NOTE: Log was too big for email and was shortened\n\n"
                "{START}[...]\n\n\n"
                "--- LOG WAS TOO BIG - ~{LINES} LINES REMOVED --\n\n\n"
                "[...]{END}".format(
                    START=log[:maxsize//2],
                    LINES=(log.count("\n", maxsize//2, -maxsize//2) + 1),
                    END=log[(-maxsize//2):])
            )
        body += log

    msg = MIMEText(body, "plain", "utf-8")
    msg['subject'] = (
        config['email']['subject']
        .replace("{STATE}", "SUCCESS" if success else "ERROR")
        .replace("{RUNTIME}", runtime)
    )

    msg['From'] = config['email']['from']
    msg['To'] = config['email']['to']

    smtp = {'host': config['email.smtp']['host']}
    if config['email.smtp']['port']:
        smtp['port'] = config['email.smtp']['port']

    server = None
    try:
        if config["email.smtp"]["ssl"]:
            server = smtplib.SMTP_SSL(**smtp)
        else:
            server = smtplib.SMTP(**smtp)
            if config['email.smtp']['tls']:
                server.starttls()

        if config['email.smtp']['user']:
            server.login(
                user=config['email.smtp']['user'],
                password=config['email.smtp']['password'])
        server.sendmail(
            from_addr=config['email']['from'],
            to_addrs=[config['email']['to']],
            msg=msg.as_string())
    except Exception as e:
        raise Exception(e)
    finally:
        if server:
            server.quit()


def send_slack_message(success, runtime):
    """send slack message

    Arguments:
        success {bool} -- processing was successful
        runtime {sting} -- script runtime
    """
    if not config['slack.message']['webhook_url']:
        raise ValueError("Failed to send Slack because webhook_url is not set")
    if not config['slack.message']['webhook_url'].startswith(
            slack_webhook_url):
                raise ValueError(
                    f"Slack URL must start with {slack_webhook_url}")

    if not config['slack.message']['text']:
        raise ValueError(
            "Failed to send Slack message because no text to send is not set")

    title = (config['slack.message']['text']
             .replace("{STATE}", "SUCCESS" if success else "ERROR")
             .replace("{RUNTIME}", runtime))
    slack_data = {
        'text': title,
        'icon_emoji': ":information_source:" if success else ":warning:",
        'pretty': 1
    }
    response = requests.post(
        url=config['slack.message']['webhook_url'],
        data=json.dumps(slack_data),
        headers={"Content-type": "application/json", "Accept": "text/plain"}
    )

    if response.status_code != 200:
        raise ("Request to Slack returned error code "
               f"{response.status_code}, the response is:\n{response.text}")


def send_slack_attachment(success, runtime):
    """send slack attachment

    Arguments:
        success {bool} -- processing was successful
        runtime {sting} -- script runtime
    """
    if not config['slack.attachment']['token']:
        raise ValueError(
            "Failed to send Slack attachment because token is not set")

    if not config['slack.attachment']['channels']:
        raise ValueError(
            "Failed to send Slack attachment because channels is not set")

    if not slack_log:
        slack_log.write("no SnapRAID output generated")

    body = f"snapraid_runner finished in {runtime}.\n\n"

    if success:
        body += "SnapRAID job completed successfully:\n\n\n"
    else:
        body += "Error during SnapRAID job:\n\n\n"

    body += slack_log.getvalue()

    formated_date = datetime.datetime.strftime(
        config['snapraid']['start'], '%Y-%m-%d_%H%M%S')

    title = (config['slack.attachment']['title']
             .replace("{STATE}", "SUCCESS" if success else "ERROR")
             .replace("{RUNTIME}", runtime))
    slack_data = {
        'initial_comment': title,
        'channels': config['slack.attachment']['channels'],
        'filetype': 'text',
        'filename': f"snapraid_{formated_date}.log",
        'pretty': 1,
    }
    response = requests.post(
        url=slack_filesUpload,
        params=slack_data,
        files={'file': bytes(body, 'utf-8')},
        headers={
            'Authorization': f"Bearer {config['slack.attachment']['token']}"
        }
    )
    if response.status_code != 200:
        raise ConnectionError("Request to Slack returned error code "
                              f"'{response.status_code}' and response '"
                              f"'{response.text}'")

    json_data = json.loads(response.text)
    if not json_data['ok']:
        raise Exception(
            f"Cannot upload Slack attachment. {json_data['error']}")


def main():
    try:
        args = parse_arguments()
    except Exception as e:
        sys.stderr.write(f"Error while parsing start arguments. {e}\n")
        sys.exit(1)

    try:
        load_config(args)
    except Exception as e:
        sys.stderr.write(f"Error while loading config. {e}\n")
        sys.exit(1)

    try:
        setup_logger()
    except Exception as e:
        sys.stderr.write("Unexpected exception while setting up logging\n")
        sys.stderr.write(f"{traceback.format_exc()}\n")
        sys.exit(1)

    if args.log_config:
        log_config()

    try:
        runner()
    except KeyboardInterrupt:
        print(flush=True)  # flush stream to prevent output mixup
        logging.warning("You manually abort")
    except Exception as e:
        logging.error(e)
        finish(False)


if __name__ == '__main__':
    main()
