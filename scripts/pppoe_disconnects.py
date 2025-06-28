#!/usr/bin/python3

import argparse
import collections
import re
import sys

LOG_FILE = '/var/log/syslog'


class Event:
    def __init__(self, line: str) -> None:
        self.line = line

    @classmethod
    def type(cls):
        return cls.__name__


class Authenticated(Event):
    def __init__(self, line: str, pid: int, login: str) -> None:
        super().__init__(line)
        self.login = login
        self.pid = pid

    def __str__(self):
        return '{} {}'.format(self.type(), self.login)


class PPPDExit(Event):
    def __init__(self, line: str, pid: int, login: str, reason: str) -> None:
        super().__init__(line)
        self.pid = pid
        self.login = login
        self.reason = reason


class LogParser:
    connect_re = re.compile(r'pppd\[(\d+)\]: PAP peer authentication succeeded for (.*)')  # noqa: W501
    disconnect_re = re.compile(r'pppd\[(\d+)\]: Exit\.$')
    remote_padt = re.compile(r'Received PADT from (\S+) session \d+, sending SIGTERM to (\d+)')  # noqa: W501
    no_echo = re.compile('pppd\[(\d+)\]: No response to \d+ echo-requests')
    lcp_terminated = re.compile(r'pppd\[(\d+)\]: LCP terminated by peer')

    def __init__(self):
        self._online = collections.defaultdict(dict)

    def parse(self, line):
        m = self.connect_re.search(line)
        if m is not None:
            pid, login = m.groups()
            self._online[pid]['login'] = login
            return Authenticated(line, pid, login)

        m = self.disconnect_re.search(line)
        if m is not None:
            pid = m.group(1)
            if pid in self._online:
                login = self._online[pid]['login']
                reason = self._online[pid].get('reason', 'unknown')
                del self._online[pid]
                return PPPDExit(line, pid, login, reason)

        m = self.remote_padt.search(line)
        if m is not None:
            pid = m.group(2)
            if pid in self._online:
                self._online[pid]['reason'] = 'PADT (client)'
        m = self.no_echo.search(line)

        if m is not None:
            pid = m.group(1)
            if pid in self._online:
                self._online[pid]['reason'] = 'No ping'

        m = self.lcp_terminated.search(line)
        if m is not None:
            pid = m.group(1)
            if pid in self._online:
                self._online[pid]['reason'] = 'PPP disconnect (client)'

        return None

    def events(self, log: str):
        for line in open(log):
            event = self.parse(line.strip())
            if event is not None:
                yield event


def stats(args):
    parser = LogParser()
    counters = collections.defaultdict(collections.Counter)
    for event in parser.events(LOG_FILE):
        if not isinstance(event, (Authenticated, PPPDExit)):
            continue
        counters[event.login][event.type()] += 1
    seq = [(counters[login][Authenticated.type()], login)
           for login in counters]
    for _, login in sorted(seq):
        print(login, counters[login][Authenticated.type()],
              counters[login][PPPDExit.type()])


def account(args):
    parser = LogParser()
    for event in parser.events(LOG_FILE):
        if not isinstance(event, (Authenticated, PPPDExit)):
            continue
        if event.login != args.login:
            continue
        if isinstance(event, Authenticated):
            print(event.line)
        else:
            print(event.line, event.reason)


def parse_args(args):
    parser = argparse.ArgumentParser(description='PPPoE log analyzer')
    subparsers = parser.add_subparsers(
        dest='action',
        title='subcommands',
    )
    subparsers.required = True
    subparsers.add_parser('stats', help='connect and disconnect stats')
    login = subparsers.add_parser('account', help='view account log')
    login.add_argument('login')
    return parser.parse_args(args)


def main():
    args = parse_args(sys.argv[1:])
    actions = {
        'stats': stats,
        'account': account,
    }
    actions[args.action](args)


if __name__ == '__main__':
    main()
