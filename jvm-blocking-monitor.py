#!/usr/bin/python
#
# jvm-blocking-monitor.py Monitor JVM threads and prints stacktraces for long blocking threads.
#               For Linux, uses BCC, eBPF.
#
# USAGE: jvm-blocking-monitor.py [-h] [-p PID | -u | -k] [-U | -K] [-f] [duration]
#
# Copyright 2021 Yuto Kawamura
# Licensed under the Apache License, Version 2.0 (the "License")
#
#
# This program includes code taken from offcputime of bcc: https://github.com/iovisor/bcc which is licensed as follows.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Jan-2016	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from sys import stderr
from time import sleep, strftime, time, localtime
import argparse
import errno
import signal
import os
import stat
import signal
import json
from collections import namedtuple
import tempfile
from subprocess import Popen

# arg validation
def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

def positive_nonzero_int(val):
    ival = positive_int(val)
    if ival == 0:
        raise argparse.ArgumentTypeError("must be nonzero")
    return ival

def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return (stack_id < 0) and (stack_id != -errno.EFAULT)

# arguments
examples = """examples:
    ./jvm-blocking-monitor.py             # trace off-CPU stack time until Ctrl-C
    ./jvm-blocking-monitor.py 5           # trace for 5 seconds only
    ./jvm-blocking-monitor.py -f 5        # 5 seconds, and output in folded format
    ./jvm-blocking-monitor.py -m 1000     # trace only events that last more than 1000 usec
    ./jvm-blocking-monitor.py -M 10000    # trace only events that last less than 10000 usec
    ./jvm-blocking-monitor.py -p 185      # only trace threads for PID 185
    ./jvm-blocking-monitor.py -t 188      # only trace thread 188
    ./jvm-blocking-monitor.py -u          # only trace user threads (no kernel)
    ./jvm-blocking-monitor.py -k          # only trace kernel threads (no user)
    ./jvm-blocking-monitor.py -U          # only show user space stacks (no kernel)
    ./jvm-blocking-monitor.py -K          # only show kernel space stacks (no user)
"""
parser = argparse.ArgumentParser(
    description="Summarize off-CPU time by stack trace",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
thread_group = parser.add_mutually_exclusive_group()
# Note: this script provides --pid and --tid flags but their arguments are
# referred to internally using kernel nomenclature: TGID and PID.
thread_group.add_argument("-p", "--pid", metavar="PID", dest="tgid",
    help="trace this PID only", type=positive_int)
thread_group.add_argument("-t", "--tid", metavar="TID", dest="pid",
    help="trace this TID only", type=positive_int)
thread_group.add_argument("-u", "--user-threads-only", action="store_true",
    help="user threads only (no kernel threads)")
thread_group.add_argument("-k", "--kernel-threads-only", action="store_true",
    help="kernel threads only (no user threads)")
stack_group = parser.add_mutually_exclusive_group()
stack_group.add_argument("-U", "--user-stacks-only", action="store_true",
    help="show stacks from user space only (no kernel space stacks)")
stack_group.add_argument("-K", "--kernel-stacks-only", action="store_true",
    help="show stacks from kernel space only (no user space stacks)")
parser.add_argument("-d", "--delimited", action="store_true",
    help="insert delimiter between kernel/user stacks")
parser.add_argument("-f", "--folded", action="store_true",
    help="output folded format")
parser.add_argument("--stack-storage-size", default=1024,
    type=positive_nonzero_int,
    help="the number of unique stack traces that can be stored and "
         "displayed (default 1024)")
parser.add_argument("duration", nargs="?", default=99999999,
    type=positive_nonzero_int,
    help="duration of trace, in seconds")
parser.add_argument("-m", "--min-block-time", default=1,
    type=positive_nonzero_int,
    help="the amount of time in microseconds over which we " +
         "store traces (default 1)")
parser.add_argument("-M", "--max-block-time", default=(1 << 64) - 1,
    type=positive_nonzero_int,
    help="the amount of time in microseconds under which we " +
         "store traces (default U64_MAX)")
parser.add_argument("--state", type=positive_int,
    help="filter on this thread state bitmask (eg, 2 == TASK_UNINTERRUPTIBLE" +
         ") see include/linux/sched.h")
parser.add_argument("--jstack", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
folded = args.folded
duration = int(args.duration)
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US    MINBLOCK_US_VALUEULL
#define MAXBLOCK_US    MAXBLOCK_US_VALUEULL

struct event_t {
    u32 pid;
    u32 tgid;
    int user_stack_id;
    int kernel_stack_id;
    char name[TASK_COMM_LEN];
    u64 offtime;
    u64 t_start;
    u64 t_end;
};
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

BPF_PERF_OUTPUT(events);

struct rq;

int oncpu(struct pt_regs *ctx, struct rq *rq, struct task_struct *prev) {
    u32 pid = prev->pid;
    u32 tgid = prev->tgid;
    u64 ts, *tsp, t_start;

    // record previous thread sleep time
    if ((THREAD_FILTER) && (STATE_FILTER)) {
        ts = bpf_ktime_get_ns();
        start.update(&pid, &ts);
    }

    // get the current thread's start time
    pid = bpf_get_current_pid_tgid();
    tgid = bpf_get_current_pid_tgid() >> 32;
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;        // missed start or filtered
    }
    t_start = *tsp;

    // calculate current thread's delta time
    u64 t_end = bpf_ktime_get_ns();
    start.delete(&pid);
    if (t_start > t_end) {
        return 0;
    }
    u64 delta = t_end - t_start;

    delta = delta / 1000;
    if ((delta < MINBLOCK_US) || (delta > MAXBLOCK_US)) {
        return 0;
    }

    // create and submit an event
    struct event_t event = {};

    event.pid = pid;
    event.tgid = tgid;
    event.user_stack_id = USER_STACK_GET;
    event.kernel_stack_id = KERNEL_STACK_GET;
    bpf_get_current_comm(&event.name, sizeof(event.name));
    event.offtime = delta;
    event.t_start = t_start;
    event.t_end = t_end;

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# set thread filter
thread_context = ""
if args.tgid is not None:
    thread_context = "PID %d" % args.tgid
    thread_filter = 'tgid == %d' % args.tgid
elif args.pid is not None:
    thread_context = "TID %d" % args.pid
    thread_filter = 'pid == %d' % args.pid
elif args.user_threads_only:
    thread_context = "user threads"
    thread_filter = '!(prev->flags & PF_KTHREAD)'
elif args.kernel_threads_only:
    thread_context = "kernel threads"
    thread_filter = 'prev->flags & PF_KTHREAD'
else:
    thread_context = "all threads"
    thread_filter = '1'
if args.state == 0:
    state_filter = 'prev->state == 0'
elif args.state:
    # these states are sometimes bitmask checked
    state_filter = 'prev->state & %d' % args.state
else:
    state_filter = '1'
bpf_text = bpf_text.replace('THREAD_FILTER', thread_filter)
bpf_text = bpf_text.replace('STATE_FILTER', state_filter)

# set stack storage size
bpf_text = bpf_text.replace('STACK_STORAGE_SIZE', str(args.stack_storage_size))
bpf_text = bpf_text.replace('MINBLOCK_US_VALUE', str(args.min_block_time))
bpf_text = bpf_text.replace('MAXBLOCK_US_VALUE', str(args.max_block_time))

# handle stack args
kernel_stack_get = "stack_traces.get_stackid(ctx, 0)"
user_stack_get = "stack_traces.get_stackid(ctx, BPF_F_USER_STACK)"
stack_context = ""
if args.user_stacks_only:
    stack_context = "user"
    kernel_stack_get = "-1"
elif args.kernel_stacks_only:
    stack_context = "kernel"
    user_stack_get = "-1"
else:
    stack_context = "user + kernel"
bpf_text = bpf_text.replace('USER_STACK_GET', user_stack_get)
bpf_text = bpf_text.replace('KERNEL_STACK_GET', kernel_stack_get)

# check for an edge case; the code below will handle this case correctly
# but ultimately nothing will be displayed
if args.kernel_threads_only and args.user_stacks_only:
    print("ERROR: Displaying user stacks for kernel threads " +
          "doesn't make sense.", file=stderr)
    exit(1)

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="finish_task_switch", fn_name="oncpu")
matched = b.num_open_kprobes()
if matched == 0:
    print("error: 0 functions traced. Exiting.", file=stderr)
    exit(1)

# header
if not folded:
    print("Tracing off-CPU time (us) of %s by %s stack" %
        (thread_context, stack_context), end="")
    if duration < 99999999:
        print(" for %d secs." % duration)
    else:
        print("... Hit Ctrl-C to end.")

class AsyncProfiler(object):
    def __init__(self, profiler_cmd_path, pid):
        self.profiler_cmd_path = profiler_cmd_path
        self.pid = pid
        self.tmpfile = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def output_path(self):
        if self.tmpfile:
            return self.tmpfile.name
        return None

    def gen_ap_cmd(self, subcommand):
        return [self.profiler_cmd_path, "-e", "none", "-o", "stream", "-f", self.output_path(), subcommand, str(self.pid)]

    def exec_profiler_cmd(self, subcommand):
        cmd = self.gen_ap_cmd(subcommand)
        status = Popen(cmd, stdout=open(os.devnull, 'w')).wait()
        if status != 0:
            raise ValueError("profiler.sh exit with error: {}".format(status))

    def start(self):
        self.tmpfile = tempfile.NamedTemporaryFile("rw", prefix="jbm-ap-")
        os.chmod(self.tmpfile.name, stat.S_IRUSR|stat.S_IWUSR|stat.S_IRGRP|stat.S_IWGRP|stat.S_IROTH|stat.S_IWOTH)
        self.exec_profiler_cmd("start")

    def stop(self):
        self.exec_profiler_cmd("stop")
        self.tmpfile.close()

class AsyncProfileStream(object):
    def __init__(self, path):
        self.fp = open(path, "r")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def next(self):
        line = self.fp.readline()
        if not line:
            return None
        return json.loads(line)

    def close(self):
        self.fp.close()
            
EVENT_MATCH_TIME_THRESHOLD_MS = 5000
EVENT_MATCH_GIVEUP_MS = 30000

StackFrame = namedtuple('StackFrame', ['address', 'symbol'])
BpfEvent = namedtuple('BpfEvent', ['timestamp', 'pid', 'tid', 'comm', 'duration_us', 'frames'])

def format_time(t):
    return "{}.{}".format(strftime("%Y-%m-%d %H:%M:%S", localtime(t / 1000)), t % 1000)

def trash_ap_event(ap_event):
    # TODO: should go to a separate file?
    print("{} DISCARDED AP EVENT TID: {}".format(format_time(ap_event['timestamp']), ap_event['tid']), file=stderr)
    for (i, frame) in enumerate(ap_event['frames']):
        print("  {}: [0x{:x}] {}".format(i, frame['methodId'], frame['symbol']), file=stderr)

def report_event(bpf_event, ap_event):
    print("=== {} PID: {}, TID: {} ({}), DURATION: {} us".format(format_time(bpf_event.timestamp), bpf_event.pid, bpf_event.tid, bpf_event.comm, bpf_event.duration_us))
    print("Native Stack:")
    for (i, frame) in enumerate(bpf_event.frames):
        print("  {}: [0x{:x}] {}".format(i, frame.address, frame.symbol))
    if ap_event:
        print("--------------------------------------------------------------------------------")
        print("JVM Stack (took: {}):".format(format_time(ap_event['timestamp'])))
        for (i, frame) in enumerate(ap_event['frames']):
            print("  {}: [0x{:x}] {}".format(i, frame['methodId'], frame['symbol']))


class EventQueues(object):
    def __init__(self):
        self.bpf_queues = {}
        self.ap_queues = {}

    @staticmethod
    def get_or_init_queue(queues, key):
        if key not in queues:
            queues[key] = []
        return queues[key]

    def fill_ap_queue(self, ap_stream):
        while True:
            event = ap_stream.next()
            if not event:
                break
            EventQueues.get_or_init_queue(self.ap_queues, event['tid']).append(event)

    def add_bpf_event(self, event):
        EventQueues.get_or_init_queue(self.bpf_queues, event.tid).append(event)

    def sweep(self):
        now = int(time() * 1000)

        for tid in self.bpf_queues.keys():
            bpf_queue = self.bpf_queues[tid]
            ap_queue = self.ap_queues.get(tid)
            while bpf_queue:
                bpf_event = bpf_queue[0]
                reported = False
                while ap_queue:
                    ap_event = ap_queue.pop(0)
                    if not ap_queue:
                        # Remove ap queue from per-TID list if it is now empty
                        del self.ap_queues[tid]
    
                    ts_diff = ap_event['timestamp'] - bpf_event.timestamp
                    if ts_diff < 0:
                        # There should be no corresponding event for this, trash it.
                        trash_ap_event(ap_event)
                    elif ts_diff < EVENT_MATCH_TIME_THRESHOLD_MS:
                        report_event(bpf_event, ap_event)
                        bpf_queue.pop(0)
                        reported = True
                        break

                if reported:
                    continue

                if now - bpf_event.timestamp >= EVENT_MATCH_GIVEUP_MS:
                    # No corresponding event found within the timeout, print the event only with
                    # stacktraces from eBPF
                    bpf_queue.pop(0)
                    report_event(bpf_event, None)
                else:
                    # An event from eBPF has no corresponding event yet, and hasn't waited enough.
                    # Subsequent events must have higher timestamp, so they will fall into the same
                    # situation too.
                    break
            if not bpf_queue:
                # Remove bpf queue from per-TID list if it is now empty
                del self.bpf_queues[tid]
        
stack_traces = b.get_table("stack_traces")


event_queues = EventQueues()

def print_event(cpu, data, size):
    timestamp = int(time() * 1000)

    event = b["events"].event(data)

    # Signal target thread for taking call trace
    os.kill(event.pid, signal.SIGPROF)

    # user stacks will be symbolized by tgid, not pid, to avoid the overhead
    # of one symbol resolver per thread
    user_stack = [] if event.user_stack_id < 0 else \
        stack_traces.walk(event.user_stack_id)
    kernel_stack = [] if event.kernel_stack_id < 0 else \
        stack_traces.walk(event.kernel_stack_id)

    frames = []
    if not args.user_stacks_only:
        if stack_id_err(event.kernel_stack_id):
            frames.append(StackFrame(address=0x0, symbol="[Missed Kernel Stack]"))
        else:
            for addr in kernel_stack:
                frames.append(StackFrame(address=addr, symbol=b.ksym(addr).decode('utf-8', 'replace')))
    if not args.kernel_stacks_only:
        if stack_id_err(event.user_stack_id):
            frames.append(StackFrame(address=0x0, symbol="[Missed User Stack]"))
        else:
            for addr in user_stack:
                frames.append(StackFrame(address=addr, symbol=b.ksym(addr).decode('utf-8', 'replace')))

    bpf_event = BpfEvent(timestamp=timestamp, pid=event.tgid, tid=event.pid, comm=event.name, duration_us=event.offtime, frames=frames)
    event_queues.add_bpf_event(bpf_event)


profiler_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "async-profiler", "profiler.sh")

with AsyncProfiler(profiler_bin, args.tgid) as ap,\
     AsyncProfileStream(ap.output_path()) as ap_stream:

     b["events"].open_perf_buffer(print_event)
     while True:
         try:
             b.perf_buffer_poll(timeout=100)
             event_queues.fill_ap_queue(ap_stream)
             event_queues.sweep()
         except KeyboardInterrupt:
             break