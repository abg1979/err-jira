# -*- coding: utf-8 -*-
from errbot import BotPlugin, CommandError
from errbot import botcmd, arg_botcmd, re_botcmd
from itertools import chain
import re
from typing import List
import subprocess

CONFIG_TEMPLATE = {
    'API_URL': 'https://jira.yours',
    'USERNAME': 'errbot',
    'PASSWORD': '',
    'PASSWORD_CMD': ['cat', '/home/errbot/.jira.password'],
    'PROJECT': 'FOO',
    'OAUTH_ACCESS_TOKEN': None,
    'OAUTH_ACCESS_TOKEN_SECRET': None,
    'OAUTH_CONSUMER_KEY': None,
    'OAUTH_KEY_CERT_FILE': None
}

try:
    from jira import JIRA, JIRAError, Issue, User
except ImportError:
    raise ImportError("Please install 'jira' python package")


class JiraServer(object):

    def __init__(self, plugin: BotPlugin) -> None:
        super().__init__()
        self.jira = None
        self.plugin = plugin

    def activate(self):
        return self._login()

    def _login_oauth(self) -> JIRA:
        """
        Login to Jira with OAUTH
        """
        api_url = self.plugin.config['API_URL']
        if self.plugin.config['OAUTH_ACCESS_TOKEN'] is None:
            message = 'oauth configuration not set'
            self.plugin.log.info(message)
            return None

        cert_file = self.plugin.config['OAUTH_KEY_CERT_FILE']
        try:
            with open(cert_file, 'r') as key_cert_file:
                key_cert_data = key_cert_file.read()
            oauth_dict = {
                'access_token': self.plugin.config['OAUTH_ACCESS_TOKEN'],
                'access_token_secret': self.plugin.config['OAUTH_ACCESS_TOKEN_SECRET'],
                'consumer_key': self.plugin.config['OAUTH_CONSUMER_KEY'],
                'key_cert': key_cert_data
            }
            authed_jira = JIRA(server=api_url, oauth=oauth_dict)
            self.plugin.log.info('logging into {} via oauth'.format(api_url))
            return authed_jira
        except JIRAError:
            message = 'Unable to login to {} via oauth'.format(api_url)
            self.plugin.log.error(message)
            return None
        except TypeError:
            message = 'Unable to read key file {}'.format(cert_file)
            self.plugin.log.error(message)
            return None

    def _login_basic(self) -> JIRA:
        """
        Login to Jira with basic auth
        """
        api_url = self.plugin.config['API_URL']
        username = self.plugin.config['USERNAME']
        password_cmd = self.plugin.config.get('PASSWORD_CMD', None)
        password = None
        if password_cmd:
            self.plugin.log.info("Executing command [%s]" % password_cmd)
            try:
                password = subprocess.check_output(password_cmd)
            except subprocess.CalledProcessError:
                self.plugin.log.error("Could not execute command [%s]" % password_cmd, exc_info=True)
        if not password:
            password = self.plugin.config.get('PASSWORD', None)
        if not password:
            self.plugin.log.error("Password not available.")
            return None
        try:
            authed_jira = JIRA(server=api_url, basic_auth=(username, password))
            self.plugin.log.info('logging into {} via basic auth'.format(api_url))
            return authed_jira
        except JIRAError:
            message = 'Unable to login to {} via basic auth'.format(api_url)
            self.plugin.log.error(message, exc_info=True)
            return None

    def _login(self) -> JIRA:
        """
        Login to Jira
        """
        self.jira = self._login_oauth()
        if self.jira is None:
            self.jira = self._login_basic()
        return self.jira

    def _login_wrapper(self, func):
        try:
            return func()
        except JIRAError as j:
            if j.status_code == 403:
                self._login()

    def search_assignable_users_for_projects(self, userstring, param) -> List[User]:
        def func():
            return self.jira.search_assignable_users_for_projects(userstring, param)

        return self._login_wrapper(func)

    def issue(self, issueid) -> Issue:
        def func():
            return self.jira.issue(issueid)

        return self._login_wrapper(func)

    def transitions(self, issue):
        def func():
            return self.jira.transitions(issue)

        return self._login_wrapper(func)

    def create_issue(self, fields):
        def func():
            return self.jira.create_issue(fields)

        return self._login_wrapper(func)

    def transition_issue(self, issueid, transition):
        def func():
            return self.jira.transition_issue(issueid, transition)

        return self._login_wrapper(func)

    def assign_issue(self, issue, name):
        def func():
            return self.jira.assign_issue(issue, name)

        return self._login_wrapper(func)

    def search_issues(self, JQL, maxResults):
        def func():
            return self.jira.search_issues(JQL, maxResults)

        return self._login_wrapper(func)


class Jira(BotPlugin):
    """
    An errbot plugin for working with Atlassian JIRA
    """

    def activate(self):
        if self.config is None:
            message = 'Jira not configured.'
            self.log.info(message)
            self.warn_admins(message)
            return

        self.jira = JiraServer(self)
        if self.jira.activate():
            super(Jira, self).activate()
        else:
            self.log.error('Failed to activate Jira plugin, maybe check the configuration')

    def configure(self, configuration: dict):
        if configuration is not None and configuration != {}:
            config = dict(chain(CONFIG_TEMPLATE.items(), configuration.items()))
        else:
            config = CONFIG_TEMPLATE
        super(Jira, self).configure(config)

    def check_configuration(self, configuration):
        """
        Check the plugin config, raise errors
        """
        if not configuration.get('API_URL', '').lower().startswith('http'):
            raise ValueError('Config validation failed for API_URL, this does not start with http')
        if not configuration.get('USERNAME', ''):
            raise ValueError('Config validation failed for USERNAME, seems empty or not set')
        if not configuration.get('PASSWORD', '') and not configuration.get('PASSWORD_CMD', ''):
            raise ValueError('Config validation failed for PASSWORD and PASSWORD_CMD, seems empty or not set')

    def get_configuration_template(self):
        """
        Returns a template of the configuration this plugin supports
        """
        return CONFIG_TEMPLATE

    def _find_one_user(self, msg, user_string):
        """
        Return one jira user corresponding to user_string.
        Stop the execution by raising a jira.CommandError if none or too many users found.
        """
        users = self.jira.search_assignable_users_for_projects(user_string, self.config['PROJECT'])
        if len(users) == 0:
            raise CommandError('No corresponding user found: {}'.format(user_string))
        elif len(users) > 1:
            raise CommandError('Too many users found: {}'.format(', '.join([u.name for u in users])))
        else:
            user = users[0]
        return user

    def _verify_issue_id(self, issue):
        """
        Verify the issue ID is valid, if not raise a jira.CommandError and stop the execution.
        """
        issue = verify_and_generate_issueid(issue)
        if issue is None:
            raise CommandError('Issue id format incorrect')
        return issue

    def _verify_transition_for_id(self, issue_id, transition_name):
        """
        Ensure that a transition `tname` (case insensitive) is valid for `issueid` and return the transition
        ID that can be used to transition the issue.
        """
        verified_issue_id = self._verify_issue_id(issue_id)
        try:
            issue = self.jira.issue(verified_issue_id)
        except JIRAError:
            raise CommandError('Error connecting to Jira, issue {} might not exist'.format(verified_issue_id))
        transitions = self.jira.transitions(issue)
        transition_to_id = dict((x['name'].lower(), x['id']) for x in transitions)
        if transition_name.lower() not in transition_to_id.keys():
            raise CommandError('Transition {} does not exist, available transitions: {}'.format(
                transition_name,
                ''.join(['\n\t- ' + x for x in transition_to_id.keys()]))
            )
        return transition_to_id[transition_name.lower()]

    @botcmd(split_args_with=' ')
    def jira_get(self, msg, args):
        """
        Describe a ticket. Usage: jira get <issue_id>
        """
        issue_id = self._verify_issue_id(args.pop(0))
        try:
            issue = self.jira.issue(issue_id)
            self.send_card(
                title=issue.fields.summary,
                summary='Jira issue {}:'.format(issue_id),
                link=issue.permalink(),
                body=issue.fields.status.name,
                fields=(
                    ('Assignee', issue.fields.assignee.displayName if issue.fields.assignee else 'None'),
                    ('Status', issue.fields.priority.name),
                ),
                color='red',
                in_reply_to=msg
            )
        except JIRAError:
            raise CommandError('Error communicating with Jira, issue {} does not exist?'.format(issue_id))

    @arg_botcmd('summary', type=str, nargs='+', help='Can end with @username to assign the task to `username`')
    @arg_botcmd('-t', dest='itype', type=str, default='Task', help='Task name')
    @arg_botcmd('-p', dest='priority', default='P3', type=str, help='Priority name')
    def jira_create(self, msg, summary, itype='Task', priority='P3'):
        """
        Creates a new issue.
        """
        summary = ' '.join(summary)
        if not summary:
            raise CommandError('You did not provide a summary.\n'
                               'Usage: jira create [-t <type>] [-p <priority>] <summary> [@user]')
        summary, user = get_username_from_summary(summary)
        if user is not None:
            user = self._find_one_user(msg, user)
        try:
            issue_dict = {
                'project': self.config['PROJECT'],
                'summary': summary,
                'description': 'Reported by {} in errbot chat'.format(msg.frm.nick),
                'issuetype': {'name': itype},
                'priority': {'name': priority}
            }
            if user is not None:
                issue_dict['assignee'] = {'name': user.name}
            issue = self.jira.create_issue(fields=issue_dict)
            self.jira_get(msg, [issue.key])
        except JIRAError:
            return 'Something went wrong when calling Jira API, please ensure all fields are valid'

    @botcmd(split_args_with=None)
    def jira_transition(self, msg, args):
        """
        Transition a ticket. Usage: jira transition <issue_id> <transition_type>
        """
        if len(args) != 2:
            raise CommandError('Wrong argument number.\nUsage: jira transition <issue_id> <transition_type>')
        issueid = self._verify_issue_id(args[0])
        transition = self._verify_transition_for_id(issueid, args[1])
        self.jira.transition_issue(issueid, transition)
        self.jira_get(msg, [issueid])

    @botcmd(split_args_with=None)
    def jira_assign(self, msg, args):
        """
        Assign a ticket. Usage: jira assign <issue_id> <username>
        """
        if len(args) != 2:
            raise CommandError('Wrong argument number.\nUsage: jira assign <issue_id> <username>')
        issueid = self._verify_issue_id(args[0])
        user = self._find_one_user(msg, args[1])
        try:
            issue = self.jira.issue(issueid)
            self.jira.assign_issue(issue, user.name)
            return 'Issue {} assigned to {}'.format(issue, user)
        except JIRAError:
            raise CommandError('Error communicating with Jira, issue {} does not exist?'.format(issueid))

    @re_botcmd(pattern=r"(^| )([^\W\d_]+)\-(\d+)( |$|\?|!\.)", prefixed=False, flags=re.IGNORECASE)
    def jira_listener(self, msg, match):
        """List for jira ID and display theyr summary"""
        try:
            self.log.info("Got message [%s]" % msg)
            self.jira_get(msg, ['-'.join(match.groups()[1:3]).upper()])
        except CommandError:
            pass

    @botcmd(split_args_with=None)
    def jira_jql(self, msg, args):
        """JQL search for a Jira tickets. Usage: jira search jql <JQL query>"""
        try:
            jql = 'project=' + self.config['PROJECT'] + ' and ' + ' '.join(args)
            for issue in self.jira.search_issues(jql, maxResults=50):
                yield '- [{}]({}) - {} - {}'.format(issue, issue.permalink(), issue.fields.status.name,
                                                    issue.fields.summary)
        except JIRAError as e:
            yield e.text

    @arg_botcmd('search', type=str, nargs='+', help='Search string')
    @arg_botcmd('--open', dest='open', action='store_true', help='Only open items')
    def jira_search(self, msg, search, open):
        """Search for a Jira tickets in description. Usage: jira search <text>"""
        args = ['(']
        args += ['summary', '~', '"'] + search + ['"']
        args += ['or', 'description', '~', '"'] + search + ['"']
        args += [')']
        if open:
            args += 'and status=Open'.split()
        args += 'order by created desc'.split()
        for x in self.jira_jql(msg, args):
            yield x

    @botcmd(split_args_with=None)
    def jira_mine(self, msg, args):
        """Shortuc to search for opened Jira items assigned to the requesting user"""
        jql_args = ['(']
        jql_args += ['assignee', '=', '{}'.format(msg.frm.person.lstrip('@'))]
        jql_args += ['AND', 'status', '!=', 'Closed']
        jql_args += [')']
        jql_args += 'order by created desc'.split()
        for x in self.jira_jql(msg, jql_args):
            yield x


def verify_and_generate_issueid(issueid):
    """
    Take a Jira issue ID lowercase, or without a '-' and return a valid Jira issue ID.
    Return None if issueid can't be transformed
    """
    matches = []
    regexes = [r'([^\W\d_]+)\-(\d+)', r'([^\W\d_]+)(\d+)']
    for regex in regexes:
        matches.extend(re.findall(regex, issueid, flags=re.I | re.U))
    if matches:
        for match in set(matches):
            return match[0].upper() + '-' + match[1]
    return None


def get_username_from_summary(summary):
    """
    If the summary string ends with `@someone`, return `someone`
    """
    last_word = summary.rsplit(None, 1)[-1]
    if last_word[0] == '@':
        return summary[:-len(last_word) - 1], last_word[1:]
    return summary, None
