'''
Created on Aug 1, 2017

Generic log utility class
The source of this file is TestPyVPX
@author: hjimin
'''

import sys
import time
import errno
import logging
import os.path
import platform

def is_windows():
    return platform.system() == 'Windows'

def is_mac_osx():
    return platform.system() == 'Darwin'

def make_dirs(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno == errno.EEXIST:
            pass
        else:
            raise

class MyFormatter(logging.Formatter):
    """Formatter class for all Log instances.

    Uses ISO 8601 date/time format in UTC, augmented with milliseconds,
    a format which is uniform with how almost all VMware components do
    date/time logging (such as the vmkernel, vmx, vmm, hostd, vpxd,
    etc.)

    The qe.* Java test-vpx tests are already outputting in this
    format, this covers the python side of things.

    Without this, logging.Formatter claims to use ISO 8601, but it
    isn't really: it's only ISO 8601 inspired, but looks nothing like
    it (eg, 2017-07-04 17:23:00,123).
    """

    def formatTime(self, record, datefmt=None):
        return '%s.%03dZ' % (time.strftime('%Y-%m-%dT%H:%M:%S',
                                           time.gmtime(record.created)),
                             record.msecs)


class Log(object):
    """Log class for the top-level runUpgrade process and all of its scrtips."""

    def __init__(self, filename='', log_dir='', console_output=False):
        self.filename = filename
        self.baseDir = 'C:\\temp' if is_windows() else '/tmp'
        if not log_dir:
            user = os.environ.get('USER') or os.environ.get('USERNAME') or 'noname'
            log_dir = os.path.join(self.baseDir, 'run-%s-%s-%s' %
                                  (user, int(time.time()), os.getpid()))
        if not os.path.isdir(log_dir):
            err_msg = "log dir does not exist. could not proceed."
            raise Exception(err_msg)
        self.logDir = log_dir
        self.logPath = os.path.join(log_dir, filename)
        self.name = os.path.splitext(filename)[0]

        # Create and configure the logger instance.
        self.logFormat = MyFormatter('%(asctime)s [%(levelname)s %(filename)s::'
                                     '%(funcName)s::%(lineno)s::%(threadName)s] %(message)s')
        self.log = logging.getLogger(self.name)
        self.log.level = logging.DEBUG

        # Initialize, create, and add the log handlers
        self.streamHandler = None
        self.fileHandler = None

        self.create_handlers(console_output)
        self.add_handlers()
        self.log.info('Command line arguments: %s' % str(sys.argv))

    def create_handlers(self, console_output=False):
        """Create a log file handler and optional log stream handler."""

        # Output to console
        if console_output:
            self.streamHandler = logging.StreamHandler(stream=sys.stdout)
            self.streamHandler.setLevel(logging.DEBUG)
            self.streamHandler.setFormatter(self.logFormat)

        # Log all messages to file
        self.fileHandler = logging.FileHandler(self.logPath, mode='a')
        self.fileHandler.setLevel(logging.DEBUG)
        self.fileHandler.setFormatter(self.logFormat)

    def add_handlers(self):
        """Add handlers to a Log instance."""

        self.log.addHandler(self.fileHandler)
        if self.streamHandler:
            self.log.addHandler(self.streamHandler)

    def remove_handlers(self):
        """Remove all handlers from a Log instance."""

        self.log.removeHandler(self.fileHandler)
        if self.streamHandler:
            self.log.removeHandler(self.streamHandler)