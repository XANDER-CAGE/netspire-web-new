# -*- coding: utf-8 -*-

from datetime import datetime
from calendar import timegm
import time

class Storage(dict):
    """
    A Storage object is like a dictionary except `obj.foo` can be used
    in addition to `obj['foo']`.
    
        >>> o = storage(a=1)
        >>> o.a
        1
        >>> o['a']
        1
        >>> o.a = 2
        >>> o['a']
        2
        >>> del o.a
        >>> o.a
        Traceback (most recent call last):
            ...
        AttributeError: 'a'
    
    """
    def __getattr__(self, key): 
        try:
            return self[key]
        except KeyError, k:
            raise AttributeError, k
    
    def __setattr__(self, key, value): 
        self[key] = value
    
    def __delattr__(self, key):
        try:
            del self[key]
        except KeyError, k:
            raise AttributeError, k
    
    def __repr__(self):     
        return '<Storage ' + dict.__repr__(self) + '>'

storage = Storage

def datetime_utc_to_local(u):
    return datetime.fromtimestamp(timegm(u.timetuple()))

def datetime_local_to_utc(l):
    return datetime.utcfromtimestamp(time.mktime(l.timetuple()))

def string_to_utc_datetime(s):
    '''Converts a date string in local time to datetime object in UTC.'''
    return datetime.utcfromtimestamp(time.mktime(time.strptime(s, '%Y-%m-%d')))

def sid(s):
    return  ':'.join(s[i*2:(i+1)*2] for i in range(6))

def interval_to_string(d):
    hours, seconds = divmod(d.seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    s = u'{:02d}:{:02d}:{:02d}'.format(hours, minutes, seconds)
    if d.days > 0:
        return u'{} д {}'.format(d.days, s)
    return s

def human_money(n):
    s = '{:.2f}'.format(n)
    whole, frac = s.split('.')
    negative = False
    if whole.startswith('-'):
        negative = True
        whole = whole[1:]
    leftmost = len(whole) % 3
    s = leftmost
    parts = []
    if leftmost > 0:
        parts.append(whole[0:leftmost])
    while s < len(whole):
        parts.append(whole[s: s+3])
        s += 3
    whole = ' '.join(parts) + '.' + frac
    if negative:
        return '-' + whole
    return whole

def int_to_money(n):
    s = str(n)[::-1]
    return (' '.join(s[i:i+3] for i in range(0, len(s), 3))[::-1])

def convert_bytes(size):
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return "%3.1f %s" % (size, x)
        size /= 1024.0

def sec_to_time(sec):
    time = datetime.fromtimestamp(sec)
    return time.strftime('%Y-%m-%d %H:%M:%S')