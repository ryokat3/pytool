#!/usr/bin/env python
# vim: set ts=4 et sw=4 sts=4 fileencoding=utf-8:
#
'''
SSH Tool
'''

import argparse
import json
import operator
import os
import paramiko
import re
import select
import signal
import socket
import sys
import threading
import time


from selectext import SelectExt


########################################################################
# Context
########################################################################

# Global variable
TOPDIR = None
JSONDIR = None

def open_write_buffer(path, mode):
    fullpath = os.path.join(TOPDIR, path)
    dirpath = os.path.dirname(fullpath)
    if not os.path.isdir(dirpath):
        os.makedirs(dirpath)
    return open(fullpath, mode)


def load_json_file(path):
    with open(os.path.join(JSONDIR, path)) as fobj:
        return json.load(fobj)


class OutputBuffer(object):

    def __init__(self, path, binary):
        self.stdout = (path == None)
        self.binary = binary

        if not self.stdout:
            self.fobj = open_write_buffer(path, 'wb' if binary else 'w')
        elif binary:
            self.fobj = sys.stdout.buffer
        else:
            self.fobj = sys.stdout

    def write(self, data):
        return self.fobj.write(data \
                if self.binary else data.decode('utf-8'))

    def flush(self):
        self.fobj.flush()

    def close(self):
        if not self.stdout:
            self.fobj.close()

########################################################################
# Main
########################################################################

def ssh_connect(host, port, user, password):

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port, user, password)

    return client


def open_channel(client, stderr=True, tty=True):

    channel = client.get_transport().open_session()
    # pty converts '\n' to '\r\n' 
    # 'stty raw' should be executed before the remote command
    if tty:
        channel.get_pty()
    channel.set_combine_stderr(stderr)
    channel.setblocking(0)

    return channel


class RpcChannel(object):

    def __init__(self, selectext, channel, outbuf, cleanup):
        self.selectext = selectext
        self.channel = channel
        self.outbuf = outbuf
        self.cleanup = cleanup

    def stop(self):
        self.cleanup()

    def __call__(self):
        rcvbuf = self.channel.recv(4096)

        if rcvbuf:
            self.outbuf.write(rcvbuf)
            self.outbuf.flush()
        else:
            self.stop()

    @staticmethod
    def start(selectext, client, cmd, output=None,
            binary=False, stderr=True, tty=True, **_nouse):

        channel = open_channel(client, stderr, tty)
        outbuf = OutputBuffer(output, binary)

        def cleanup():
            outbuf.close()
            channel.close()
            selectext.unset_reader(channel)

        reader = RpcChannel(selectext, channel, outbuf, cleanup)
        selectext.set_reader(channel, reader)

        channel.exec_command(cmd)

        return reader.stop


class ExpectChannel(object):

    def __init__(self, selectext, channel, explist, outbuf, \
            timeout, cleanup):
        self.selectext = selectext
        self.channel = channel
        self.explist = explist
        self.outbuf = outbuf
        self.timeout = timeout
        self.cleanup = cleanup
        self.popexp()

    def popexp(self):
        self.regex = self.explist[0]['expect']
        self.cmd = self.explist[0]['send']
        self.explist = self.explist[1:]
        self.buf = b''

    def timer(self):

        self.outbuf.write(self.buf)
        self.outbuf.flush()

        if re.search(self.regex, self.buf.decode('utf-8'), re.M):
            self.channel.send(self.cmd + '\n')
        else:
            # Unexpected string
            self.stop()

        # Next expect
        if len(self.explist) > 0:
            self.popexp()
        else:
            self.stop()

    def __call__(self):
        if len(self.buf) == 0:
            self.selectext.set_timer(self.timeout, self.timer)
        try:
            self.buf = self.buf + self.channel.recv(4096)
        except socket.timeout:
            pass

    def stop(self):
        self.cleanup()

    @staticmethod
    def start(selectext, client, expect_list, output=None,
            timeout=1.0, stderr=True, tty=True, **_nouse):

        channel = open_channel(client, stderr, tty)
        outbuf = OutputBuffer(output, binary=False)

        def cleanup():
            outbuf.close()
            channel.close()
            selectext.unset_reader(channel)

        reader = ExpectChannel(selectext, channel, expect_list, \
                outbuf, timeout, cleanup)
        selectext.set_reader(channel, reader)

        channel.invoke_shell()

        return reader.stop


########################################################################
# Main
########################################################################

def start_channel(selectext, client, channel_type, **dic):

    if channel_type == 'rpc':
        return RpcChannel.start(selectext, client, **dic)
    elif channel_type == 'shell':
        return ExpectChannel.start(selectext, client, **dic)
    else:
        raise Exception("Unknown SSH type: ", channel_type)


def start_ssh(selectext, host, user, password, channel, port=22, **_unused):

    client = ssh_connect(host, port, user, password)

    if isinstance(channel, str):
        channel = load_json_file(channel)

    if isinstance(channel, list):
        stop_list = [ start_channel(selectext, client, **dic) \
                for dic in channel ]
        def _():
            for stop in stop_list:
                stop()
            client.close()
        return _
    else:
        stop = start_channel(selectext, client, **channel)
        def _():
            stop()
            client.close()
        return _


def start_tool(selectext, root):

    if isinstance(root, list):
        stop_list = [ start_ssh(**dic) for dic in root ]
        def _stop():
            for stop in stop_list:
                stop()
        return _stop
    else:
        return start_ssh(selectext, **root)


def sshtool(root):
    selectext = SelectExt()
    stop = start_tool(selectext, root)

    try:
        while selectext.wait():
            if len(selectext.readers.keys()) == 0:
                break
    except KeyboardInterrupt:
        selectext.notify()
        stop()


########################################################################
# Configuration
########################################################################

def get_argparser():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('jsonfile', type=str, help="JSON File")
    parser.add_argument('-t', action='store', dest='topdir',
            default='.', help='top directory on which data is stored')

    return parser


if __name__ == '__main__':
    args = get_argparser().parse_args()

    # Global variable
    TOPDIR = args.topdir

    with open(args.jsonfile, 'r') as fobj:
        JSONDIR=os.path.dirname(args.jsonfile)
        sshtool(json.load(fobj))
