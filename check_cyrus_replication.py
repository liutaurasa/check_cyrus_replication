#!python
# Copyright (c) gocept gmbh & co. kg
# See also LICENSE.txt

"""
Nagios/Icinga plugin to check Cyrus IMAP replication.
The script depends on python-nagiosplugin library.
https://github.com/sammcj/python-nagiosplugin 

Plugin checks multiple IMAP servers (multiple --uri options) for a status of mailboxes
(with IMAP STATUS command) and compares the output. Mailboxes with different statuses
are considered out of sync. The status of the mailbox on the first server will be taken
as a reference.

Plugin uses --admin (and --passw) and --user options for Cyrus IMAP proxy authorization.
Multiple --user options can be provided and script will check status of mailboxes for
all specified users. If --all-mailboxes is not specified only INBOX status for the given
user will be checked.

With --all-mailboxes parameter plugin will check and compare status of all mailboxes
accessible for the given user.

Option --all-users will make plugin to guess all possible users on the first server
specified with --uri option. The all users guess algorithm is not reliable, it tries to
compile a list of all users based on name of top level mailboxes under user/ namespace.
For example cyrus-admin user may get list of mailboxes:
user/john.doe@example.net
user/tom.smith@example.com
The plugin will guess that there are 2 users named
john.doe@example.net and tom.smith@example.com
As a consequence mailboxes without a valid user (owner) will produce a invalid_user.

Running IMAP STATUS on multiple mailboxes is time consuming therefore the script is designed
to use timeout (runs at least <--timeout> seconds until all mailboxes for current
user are checked) and use --status-file to keep track what has been checked so far,
which user to start at on next check and which users are invalid. 
The list of invalid_users can also be used to sanitise IMAP mailboxes.
One can use jq bash utility to get info from status file: jq .<param> <status-file>,
where param can be: ".invalid_users", ".statuses" or ".checked". Plugin parameter 
--failed-only should be used when only out of sync mailboxes should be checked. It is
useful when replication problem is fixed and one does not want to wait until plugin run
through all users.

Plugin supports Nagios extra options configuration file. Command line parameters can be
specified in a .ini file. That is important for security reasons (not using password on
a command line). One can specify multiple sections in the same ini file with different
sets of users and servers to be checked, which makes it convenient way of checking multiple
replicated backend servers.
"""

import argparse
import logging
import nagiosplugin
import subprocess
import time
import pprint

try:
    import cyruslib
except:
    print('Python cyruslib not installed!')
    sys.exit(3)


_log = logging.getLogger('nagiosplugin')

# data acquisition

class Replication(nagiosplugin.Resource):
    """Domain model: Cyrus IMAP Replication status
    Checks Cyrus Servers with IMAP STATUS command and compares
    results. Correctly replicating servers must return the same
    status for the same mailbox on any server
    """

    def __init__(self, *args, **kw):
        self.all_mailboxes = args[0].all_mailboxes
        self.admin = args[0].admin
        self.passw = args[0].passw
        self.servers = args[0].uri
        self.failed_only = args[0].failed_only
        self.start = time.time()
        self.statefile = args[0].state_file
        self.timeout = args[0].timeout
        self.status_cmd = args[0].status_cmd

        self.cookie = nagiosplugin.Cookie(self.statefile)

        self.invalid_users = self.get_cookie('invalid_users')
        self.checked = self.get_cookie('checked')

        if args[0].all_users:
            self.users = self.get_users()
        else:
            self.users = args[0].user

        self.statuses = self.get_cookie('statuses')
        self.out_of_sync = None

        if self.failed_only:
            self.users = [
                u for u in self.statuses for m in self.statuses[u] if len(set(self.statuses[u][m])) > 1
            ]

    def __enter__(self):
        return self

    def login(self, server, admin, passw, user=None):
        """ Send STATUS command to a server for a mailbox """

        try:
            _log.debug('Connecting into %s' % server)
            _conn = cyruslib.CYRUS(server)
            _log.debug('Logging into %s' % server)
            if user is None:
                _conn.login(admin, passw)
            else:
                _conn.login_plain(admin, passw, user)
        except Exception as err:
            _log.error("Login to server %s as user %s failed: %s" % (server, user, err))
            _conn = False
        finally:
            return _conn

    def logout(self, conn):
        """ Close connection """
        conn.logout()

    def set_cookie(self, key='statuses', value={}):
        """ Write status into state file """
        with self.cookie as cookie:
            cookie[key] = value

    def get_cookie(self, key='statuses'):
        """ Get status from state file """
        self.cookie.open()
        with self.cookie as cookie:
            if key in cookie:
                return cookie[key]
            else:
                if key == 'statuses': return {}
                elif key == 'invalid_users': return []
                elif key == 'checked': return []

    def get_status(self, conn, mbox='INBOX', cmd=None):
        """ Issue IMAP STATUS command on the mailbox """
        if cmd is None:
            cmd = self.status_cmd
        return conn.m.status(mbox, cmd)[1][0].replace(mbox, "").replace('""', "").strip()

    def get_users(self):
        """ Get list of users """
        users = []
        conn = self.login(self.servers[0], self.admin, self.passw)
        resp, subs = conn.m.list("", "%/%")
        if resp == "OK":
            for sub in subs:
                sub = sub.split()[-1]
                if sub.startswith('user'):
                    for folder in conn.lm(sub.replace('user@', 'user/%@')):
                        user = folder.replace('user/', '')
                        if not user in self.invalid_users:
                            users.append(user)

        conn.logout()
        return users

    def probe(self):
        conns = []
        if len(self.checked) >= len(self.users):
            _log.debug("Clearing cookine")
            self.checked = []
            self.set_cookie('checked', self.checked)

        for user in self.users:

            # Determine if we should check mailbox status for that user
            if user in self.checked and not self.failed_only:
                _log.debug('User %s already checked, next' % user)
                continue

            self.statuses[user] = {}

            # Create connections
            conns = []
            for server in self.servers:
                _conn = self.login(server, self.admin, self.passw, user)
                if _conn:
                    conns.append(_conn)
                else:
                    self.invalid_users.append(user)
                    self.set_cookie('invalid_users', self.invalid_users)
                    break

            # Create list of mailboxes
            if len(conns) > 1:
                # Take 1st server as basis for list of mailboxes
                if self.all_mailboxes is False:
                    self.mboxlist = ['INBOX',]
                else:
                    # Mailbox list on first connection as a reference
                    self.mboxlist = set(conns[0].lm())
            else:
                _log.error("Only one or less connection, nothing to compare with")
                continue

            
            for mbox in self.mboxlist:
                _log.debug("Checking mailbox %s: %s" % (user, mbox))
                self.statuses[user][mbox] = []
                for conn in conns:
                    self.statuses[user][mbox].append(self.get_status(conn, mbox))

            self.checked.append(user)

            for conn in conns:
                self.logout(conn)

            self.set_cookie('statuses', self.statuses)
            self.set_cookie('checked', self.checked)

            if time.time() - self.start > self.timeout:
                _log.debug("Timeout")
                break

        # Comprehention calculats mailboxes which have different status resoponses 
        self.out_of_sync = [
           {u: (m, self.statuses[u][m])} for u in self.statuses for m in self.statuses[u] if len(set(self.statuses[u][m])) > 1
        ]

        yield nagiosplugin.Metric('total checked', len([ m for u in self.statuses for m in self.statuses[u] ]), min=1, context='status')
        yield nagiosplugin.Metric('out of sync', len(self.out_of_sync), min=0, context='outofsync')

# data presentation

class MailboxSummary(nagiosplugin.Summary):
    """Status line conveying load information.

    We specialize the `ok` method to present all three figures in one
    handy tagline. In case of problems, the single-load texts from the
    contexts work well.
    """

    def ok(self, results):
        return 'Cyrus replication STATUS is OK'

    def problem(self, results):
        return 'Cyrus replication is OUT OF SYNC'

    def verbose(self, results):
        if not len(results['out of sync'].resource.out_of_sync) == 0:
            return 'Out of sync mailboxes\n%s' % pprint.pformat(results['out of sync'].resource.out_of_sync)

# runtime environment and data evaluation

@nagiosplugin.guarded(verbose=None)
def main():
    argp = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    argp.add_argument('-w', '--warning', metavar='RANGE', default='1',
                        help='return warning if load is outside RANGE')
    argp.add_argument('-c', '--critical', metavar='RANGE', default='1',
                        help='return critical if load is outside RANGE')
    argp.add_argument('-t', '--timeout', default=10, type=float,
                        help='Timeout value, not run check more than that')
    argp.add_argument('-s', '--state-file', default='/tmp/cyrus-replication-status.file',
                        help='Use statefile to track what was already checked')
    argp.add_argument('-f', '--failed-only', action='store_true', default=False,
                        help='Check only out of sync mailboxes. Need --state-file to get current status info')
    argp.add_argument('--status-cmd', default='(MESSAGES RECENT UNSEEN)',
                        help='IMAP STATUS command parameters to be used when checking mailbox status')

    argp.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increase output verbosity (use up to 3 times). One time will show out of sync mailboxes')
    
    argp.add_argument( "--extra-opts",  dest="extra_opts", action="store", default=None,
                        help='Nagios Extra Options file. Use file instead of command line parameters')

    argp.add_argument('--uri', action='append', default=[],
                        help='Cyrus server participating in replication. Use multiple times')
    argp.add_argument('--admin', default='cyrus-admin',
                        help='Cyrus admin user name, defaults to cyrus-admin')
    argp.add_argument('--passw', 
                        help='Cyrus admin user password')
    argp.add_argument('--user', action='append', default=[],
                        help='User which mailboxes status will be checked. Use multiple times on command line or in Nagios extra options file')
    argp.add_argument('--all-users', action='store_true', default=False,
                        help='Get all users from the first server in the list. Overides --user. Users are guessed from top level mailboxes under user/ namespace')
    argp.add_argument('--all-mailboxes', dest='all_mailboxes', action='store_true', default=False,
                        help='Check all mailboxes user can access, defaults to False to check only INBOX')

    args = argp.parse_args()

    if args.verbose == 0:
        _log.setLevel("NOTSET")
    elif args.verbose == 3:
        _log.setLevel("DEBUG")
    elif args.verbose == 2:
        _log.setLevel("INFO")
    elif args.verbose == 1:
        _log.setLevel("WARNING")

    if args.extra_opts is not None:
        from ConfigParser import ConfigParser
        _log.debug("Reading Extra Opts file")
        config = ConfigParser()
        cfg_section, cfg_files = args.extra_opts.split('@', 1)
        if len(cfg_files) == 0:
            cfg_files = [      
                '/etc/nagios/plugins.ini',
                '/usr/local/nagios/etc/plugins.ini',
                '/usr/local/etc/nagios/plugins.ini',
                '/etc/opt/nagios/plugins.ini',
                '/etc/nagios-plugins.ini',
                '/usr/local/etc/nagios-plugins.ini',
                '/etc/opt/nagios-plugins.ini'
            ]

        config.read(cfg_files)
        if config.has_section(cfg_section):
            for item, value in config.items(cfg_section):
                if hasattr(args, item):
                    if isinstance(eval('args.%s' % item), list):
                        setattr(args, item, value.split('\n'))
                    else:
                        setattr(args, item, value)
        else:
            _log.critical("Config file %s does not have section %s" % (cfg_files, cfg_section))


    check = nagiosplugin.Check(
        Replication(args),
        nagiosplugin.ScalarContext('status', 0, 0),
        nagiosplugin.ScalarContext('outofsync', args.warning, args.critical),
        MailboxSummary())
    check.main(verbose=args.verbose)
    # check.main()

if __name__ == '__main__':
    main()
