# check_cyrus_replication
Nagios plugin to check Cyrus IMAP replication status

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
