# snapraid-runner

This Script runs SnapRAID and sends it output to the console, a log file, via eMail and/or Slack. It runs `diff` before `sync` to see how many files were deleted, updated, copied, moved or restored and aborts if that number exceeds the set threshold. It can run `touch` before and `scrub` after `sync`.  
If configured, it also runs `smart`.  
All this is configurable in the config file or by overriding with start arguments.

## Usage

```bash
snapraid_runner.py [-h] [-v] [--log-config] [-c PATH]
                   [--verbose | --no-verbose] [--no-addthreshold]
                   [--no-removethreshold] [--no-updatethreshold]
                   [--no-copythreshold] [--no-movethreshold]
                   [--no-restorethreshold] [--touch | --no-touch]
                   [--scrub | --no-scrub] [--smart | --no-smart]
                   [--mail | --no-mail | --force-mail]
                   [--short-mail | --long-mail]
                   [--message | --no-message | --force-message]
                   [--attachment | --no-attachment | --force-attachment]
                   [--short-attachment | --long-attachment]
```

## optional arguments

| parameter     | description                                                                          |
| ------------- | ------------------------------------------------------------------------------------ |
| -h, --help    | show this help message and exit                                                      |
| -v, --version | show program's version number and exit                                               |
| --log-config  | log used config. (confidential config entries like Password or eMail will be pruned) |
| -c PATH       | path to configuration file (default: snapraid_runner.conf)                           |

## arguments to override config

| parameter             | description                                                   |
| --------------------- | ------------------------------------------------------------- |
| --verbose             | set SnapRAID output to verbose                                |
| --no-verbose          | do not set SnapRAID output to verbose                         |
| --no-addthreshold     | do not use add threshold                                      |
| --no-removethreshold  | do not use delete threshold                                   |
| --no-updatethreshold  | do not use update threshold                                   |
| --no-copythreshold    | do not use copy threshold                                     |
| --no-movethreshold    | do not use move threshold                                     |
| --no-restorethreshold | do not use restore threshold                                  |
| --touch               | run touch before sync                                         |
| --no-touch            | do not run touch                                              |
| --scrub               | run scrub after sync                                          |
| --no-scrub            | do not run scrub                                              |
| --smart               | run smart after sync                                          |
| --no-smart            | do not run smart                                              |
| --mail                | send an eMail                                                 |
| --no-mail             | do not send an eMail                                          |
| --force-mail          | ignore 'sendon' and send always an eMail                      |
| --short-mail          | do not send full SnapRAID output as eMail                     |
| --long-mail           | send full SnapRAID output as eMail                            |
| --message             | send a Slack message                                          |
| --no-message          | do not send a Slack message                                   |
| --force-message       | ignore 'sendon' and send always a Slack message               |
| --attachment          | send a Slack attachment                                       |
| --no-attachment       | do not send a Slack attachment                                |
| --force-attachment    | ignore 'sendon' and send always a Slack attachment            |
| --short-attachment    | do not send full SnapRAID output as Slack attachment          |
| --long-attachment     | send full SnapRAID output as Slack attachment                 |

created by [gi8lino](https://github.com/gi8lino/snapraid-runner)  
inspired by [snapraid-runner](https://github.com/Chronial/snapraid-runner)
