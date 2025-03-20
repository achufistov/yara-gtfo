/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2025-03-01
   Identifier: false-negative-bins
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule false_negative_bins_taskset {
   strings:
      $s1 = "%d: %s: don't print memory addresses (SUID executable)." fullword ascii
      $s2 = "failed to get pid %d's affinity" fullword ascii
      $s3 = "The default behavior is to run a new command:" fullword ascii
      $s4 = "Show or change the CPU affinity of a process." fullword ascii
      $s5 = "Usage: %s [options] [mask | cpu-list] [pid|cmd [args...]]" fullword ascii
      $s6 = " -a, --all-tasks         operate on all the tasks (threads) for a given pid" fullword ascii
      $s7 = " reading '%s'" fullword ascii
      $s8 = "failed to set pid %d's affinity" fullword ascii
      $s9 = "ul_path_get_dirfd" fullword ascii
      $s10 = "sched_getaffinity" fullword ascii
      $s11 = " fscanf [%s] '%s'" fullword ascii
      $s12 = "bad usage" fullword ascii
      $s13 = " -p, --pid               operate on existing given pid" fullword ascii
      $s14 = "ulprocfs" fullword ascii
      $s15 = "pid %d's new affinity list: %s" fullword ascii
      $s16 = "access '%s' [no context, rc=%d]" fullword ascii
      $s17 = "/proc/%d/%s" fullword ascii
      $s18 = "pid %d's current affinity list: %s" fullword ascii
      $s19 = "cpuset_alloc failed" fullword ascii
      $s20 = "failed to parse CPU mask: %s" fullword ascii
      $s21 = "new prefix: '%s'" fullword ascii
      $s22 = "opening '%s'%s" fullword ascii
      $s23 = "internal error: conversion from cpuset to string failed" fullword ascii
      $s24 = "opening '%s' [no context]" fullword ascii
      $s25 = "stat '%s' [rc=%d]" fullword ascii
      $s26 = "pid %d's new affinity mask: %s" fullword ascii
      $s27 = "pid %d's current affinity mask: %s" fullword ascii
      $s28 = "failed to parse CPU list: %s" fullword ascii
      $s29 = "stat '%s' [no context, rc=%d]" fullword ascii
      $s30 = "    %1$s 03 sshd -b 1024" fullword ascii
      $s31 = "List format uses a comma-separated list instead of a mask:" fullword ascii
      $s32 = "access: '%s' [rc=%d]" fullword ascii
      $s33 = "opening dir: '%s'" fullword ascii
      $s34 = "%d: %s: %8s: " fullword ascii
      $s35 = "init procfs stuff" fullword ascii
      $s36 = "closing dir" fullword ascii
      $s37 = "alloc new procfs handler" fullword ascii
      $s38 = "ulpath" fullword ascii
      $s39 = "__isoc99_vfscanf" fullword ascii
      $s40 = "deinit" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_git {
   strings:
      $s1 = "dropping %s %s -- patch contents already upstream" fullword ascii
      $s2 = "gpg.ssh.defaultKeyCommand failed: %s %s" fullword ascii
      $s3 = "Could not run 'git rev-list <commits> --not --remotes -n 1' command in submodule %s" fullword ascii
      $s4 = "ExecStart=\"%s/git\" --exec-path=\"%s\" for-each-repo --config=maintenance.repo maintenance run --schedule=%%i" fullword ascii
      $s5 = "%%s %%s * * %%s \"%s/git\" --exec-path=\"%s\" for-each-repo --config=maintenance.repo maintenance run --schedule=%%s" fullword ascii
      $s6 = "x, exec <command> = run command (the rest of the line) using shell" fullword ascii
      $s7 = "fast-import: dumping crash report to %s" fullword ascii
      $s8 = "git archive --remote <repo> [--exec <cmd>] --list" fullword ascii
      $s9 = "gpg.ssh.defaultKeyCommand succeeded but returned no keys: %s %s" fullword ascii
      $s10 = "sendemail.smtpReloginDelay" fullword ascii
      $s11 = "use '%s -f -f' to override, or 'unlock' and 'prune' or 'remove' to clear" fullword ascii
      $s12 = "%%(align:%d,left)%s%%(refname:lstrip=2)%%(end)%s%%(if)%%(symref)%%(then) -> %%(symref:short)%%(else) %s %%(contents:subject)%%(e" ascii
      $s13 = "%%(align:%d,left)%s%%(refname:lstrip=2)%%(end)%s%%(if)%%(symref)%%(then) -> %%(symref:short)%%(else) %s %%(contents:subject)%%(e" ascii
      $s14 = "unable to restore logfile %s from logs/refs/.tmp-renamed-log: %s" fullword ascii
      $s15 = "Could not execute the todo command" fullword ascii
      $s16 = "unable to copy logfile logs/%s to logs/refs/.tmp-renamed-log: %s" fullword ascii
      $s17 = "graph->mapping[i - 1] > target" fullword ascii
      $s18 = "tar.tgz.command" fullword ascii
      $s19 = "git ls-remote [--heads] [--tags] [--refs] [--upload-pack=<exec>]" fullword ascii
      $s20 = "*** Commands ***" fullword ascii
      $s21 = "tortoiseplink.exe" fullword ascii
      $s22 = "<Arguments>--exec-path=\"%s\" for-each-repo --config=maintenance.repo maintenance run --schedule=%s</Arguments>" fullword ascii
      $s23 = "tar.tar.gz.command" fullword ascii
      $s24 = "rebase.rescheduleFailedExec" fullword ascii
      $s25 = "empty exec command" fullword ascii
      $s26 = "Execution of '%s %s' failed in submodule path '%s'" fullword ascii
      $s27 = "unable to move logfile logs/%s to logs/refs/.tmp-renamed-log: %s" fullword ascii
      $s28 = "<Command>\"%s\\git.exe\"</Command>" fullword ascii
      $s29 = "running trailer command '%s' failed" fullword ascii
      $s30 = "failed to run command '%s': %s" fullword ascii
      $s31 = "git rebase [-i] [options] [--exec <cmd>] [--onto <newbase> | --keep-base] [<upstream> [<branch>]]" fullword ascii
      $s32 = "  git config --global user.email \"you@example.com\"" fullword ascii
      $s33 = "gpg.ssh.defaultKeyCommand" fullword ascii
      $s34 = "git rebase [-i] [options] [--exec <cmd>] [--onto <newbase>] --root [<branch>]" fullword ascii
      $s35 = "error reading from textconv command '%s'" fullword ascii
      $s36 = "NACK unable to spawn subprocess" fullword ascii
      $s37 = "or --ff-only on the command line to override the configured default per" fullword ascii
      $s38 = "error processing config file(s)" fullword ascii
      $s39 = "initialization for subprocess '%s' failed" fullword ascii
      $s40 = "gpg.ssh.defaultkeycommand" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 11000KB and
      8 of them
}

rule false_negative_bins_choom {
   strings:
      $s1 = "%d: %s: don't print memory addresses (SUID executable)." fullword ascii
      $s2 = " %1$s [options] -n number [--] command [args...]]" fullword ascii
      $s3 = " -p, --pid <num>        process ID" fullword ascii
      $s4 = " %1$s [options] -n number -p pid" fullword ascii
      $s5 = " %1$s [options] -p pid" fullword ascii
      $s6 = "no PID or COMMAND specified" fullword ascii
      $s7 = " reading '%s'" fullword ascii
      $s8 = "failed to read OOM score value" fullword ascii
      $s9 = "failed to read OOM score adjust value" fullword ascii
      $s10 = "ul_path_get_dirfd" fullword ascii
      $s11 = "failed to set score adjust value" fullword ascii
      $s12 = " fscanf [%s] '%s'" fullword ascii
      $s13 = "access '%s' [no context, rc=%d]" fullword ascii
      $s14 = "new prefix: '%s'" fullword ascii
      $s15 = "opening '%s'%s" fullword ascii
      $s16 = "opening '%s' [no context]" fullword ascii
      $s17 = "stat '%s' [rc=%d]" fullword ascii
      $s18 = "stat '%s' [no context, rc=%d]" fullword ascii
      $s19 = "access: '%s' [rc=%d]" fullword ascii
      $s20 = "opening dir: '%s'" fullword ascii
      $s21 = "pid %d's current OOM score adjust value: %d" fullword ascii
      $s22 = "1c6bf631023eb70dd8894c7bb88eddfbf20746.debug" fullword ascii
      $s23 = "pid %d's current OOM score: %d" fullword ascii
      $s24 = "pid %d's OOM score adjust value changed from %d to %d" fullword ascii
      $s25 = "%d: %s: %8s: " fullword ascii
      $s26 = "closing dir" fullword ascii
      $s27 = "invalid adjust argument" fullword ascii
      $s28 = "ulpath" fullword ascii
      $s29 = "__isoc99_vfscanf" fullword ascii
      $s30 = " [redirected]" fullword ascii
      $s31 = "invalid PID argument" fullword ascii
      $s32 = "%s/%s.XXXXXX" fullword ascii
      $s33 = "__openat_2" fullword ascii
      $s34 = "ul_path_is_accessible" fullword ascii
      $s35 = "lib/fileutils.c" fullword ascii
      $s36 = "ul_path_set_prefix" fullword ascii
      $s37 = "/proc/self/fd/%d" fullword ascii
      $s38 = "__sched_cpualloc" fullword ascii
      $s39 = "(re)set dialect" fullword ascii
      $s40 = "new dir: '%s'" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_readelf {
   strings:
      $s1 = "  -z --decompress        Decompress section before dumping it" fullword ascii
      $s2 = "This is a GO binary file - try using 'go tool objdump' or 'go tool nm'" fullword ascii
      $s3 = "  -w --debug-dump[a/=abbrev, A/=addr, r/=aranges, c/=cu_index, L/=decodedline," fullword ascii
      $s4 = "Hex dump of section '%s' in linked file %s:" fullword ascii
      $s5 = "String dump of section '%s' in linked file %s:" fullword ascii
      $s6 = " <Target Specific macro op: %#x - UNHANDLED" fullword ascii
      $s7 = "Encoded size of %d is too large to read" fullword ascii
      $s8 = "  -x --hex-dump=<number|name>" fullword ascii
      $s9 = "  -p --string-dump=<number|name>" fullword ascii
      $s10 = "  -C --demangle[=STYLE]  Decode mangled/processed symbol names" fullword ascii
      $s11 = "Raw dump of debug contents of section %s (loaded from %s):" fullword ascii
      $s12 = "NT_GDB_TDESC (GDB XML target description)" fullword ascii
      $s13 = "internal error: attempt to read %d bytes of data in to %d sized variable" fullword ascii
      $s14 = "internal error: attempt to read %d byte of data in to %d sized variable" fullword ascii
      $s15 = "Dump of CTF section '%s' in linked file %s:" fullword ascii
      $s16 = "Encoded size of 0 is too small to read" fullword ascii
      $s17 = "  -P --process-links     Display the contents of non-debug sections in separate" fullword ascii
      $s18 = " DW_MACRO_start_file - lineno: %d filenum: %d filename: %s%s%s" fullword ascii
      $s19 = "  -wK --debug-dump=follow-links" fullword ascii
      $s20 = "  -wk --debug-dump=links Display the contents of sections that link to separate" fullword ascii
      $s21 = ", AVC coprocesso, AVC2 coprocess, FMAX coprocess, IVC2 coprocess, Built for Libr, V3 architectur, regmode: COMMO, double precisi" ascii
      $s22 = "Broadcom VideoCore V processor" fullword ascii
      $s23 = "  -wN --debug-dump=no-follow-links" fullword ascii
      $s24 = "Unknown attributes version '%c'(%d) - expecting 'A'" fullword ascii
      $s25 = ", AVC coprocesso, AVC2 coprocess, FMAX coprocess, IVC2 coprocess, Built for Libr, V3 architectur, regmode: COMMO, double precisi" ascii
      $s26 = "Contents of the SFrame section %s:" fullword ascii
      $s27 = "Atmel Corporation 32-bit microprocessor" fullword ascii
      $s28 = "The length field (%#lx) in the debug_line header is wrong - the section is too small" fullword ascii
      $s29 = "Dump of CTF section '%s':" fullword ascii
      $s30 = "filedata->dump.num_dump_sects >= cmdline.num_dump_sects" fullword ascii
      $s31 = "The length field (%#lx) in the debug_rnglists header is wrong - the section is too small" fullword ascii
      $s32 = "KIPO-KAIST Core-A 1st generation processor family" fullword ascii
      $s33 = "No processor specific unwind information to decode" fullword ascii
      $s34 = "KIPO-KAIST Core-A 2nd generation processor family" fullword ascii
      $s35 = "Too many program headers - %#x - the file is not that big" fullword ascii
      $s36 = "dump_sframe" fullword ascii
      $s37 = "Compiled with branch target enforcement" fullword ascii
      $s38 = "Section '%s' was not dumped because it does not exist" fullword ascii
      $s39 = "Compiled without branch target enforcement" fullword ascii
      $s40 = "%s: Corrupt entry count - expected %#lx but none found" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule false_negative_bins_unshare {
   strings:
      $s1 = "%d: %s: don't print memory addresses (SUID executable)." fullword ascii
      $s2 = " --map-users=<outeruid>,<inneruid>,<count>" fullword ascii
      $s3 = "unsupported --setgroups argument '%s'" fullword ascii
      $s4 = " -R, --root=<dir>          run the command with root directory set to <dir>" fullword ascii
      $s5 = " --propagation slave|shared|private|unchanged" fullword ascii
      $s6 = "xgetgrnam" fullword ascii
      $s7 = "xgetpwuid" fullword ascii
      $s8 = "xgetpwnam" fullword ascii
      $s9 = "unshare failed" fullword ascii
      $s10 = "failed to read eventfd" fullword ascii
      $s11 = "unshare" fullword ascii
      $s12 = "                           map count users from outeruid to inneruid (implies --user)" fullword ascii
      $s13 = " --map-group=<gid>|<name>  map current group to gid (implies --user)" fullword ascii
      $s14 = "failed to write to /proc/self/timens_offsets" fullword ascii
      $s15 = " -u, --uts[=<file>]        unshare UTS namespace (hostname etc)" fullword ascii
      $s16 = "failed to open /proc/self/timens_offsets" fullword ascii
      $s17 = " reading '%s'" fullword ascii
      $s18 = "stat of %s failed" fullword ascii
      $s19 = "too many elements for mapping '%s'" fullword ascii
      $s20 = "no line matching user \"%s\" in %s" fullword ascii
      $s21 = "capget failed" fullword ascii
      $s22 = "mapping '%s' contains only %d elements" fullword ascii
      $s23 = "mount %s failed" fullword ascii
      $s24 = "map-root-user" fullword ascii
      $s25 = "you (user %d) don't exist." fullword ascii
      $s26 = "mount %s on %s failed" fullword ascii
      $s27 = "ul_path_get_dirfd" fullword ascii
      $s28 = "waitpid failed" fullword ascii
      $s29 = "sigprocmask block failed" fullword ascii
      $s30 = "failed to parse boottime offset" fullword ascii
      $s31 = "failed to parse uid" fullword ascii
      $s32 = "sigprocmask restore failed" fullword ascii
      $s33 = "setuid failed" fullword ascii
      $s34 = "setgroups failed" fullword ascii
      $s35 = " -r, --map-root-user       map current user to root (implies --user)" fullword ascii
      $s36 = "sigprocmask unblock failed" fullword ascii
      $s37 = "eventfd failed" fullword ascii
      $s38 = "child exit failed" fullword ascii
      $s39 = "failed to parse gid" fullword ascii
      $s40 = "prctl failed" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_ionice {
   strings:
      $s1 = " %1$s [options] <command>" fullword ascii
      $s2 = "ioprio_get failed" fullword ascii
      $s3 = " -u, --uid <uid>...     act on already running processes owned by these users" fullword ascii
      $s4 = "Show or change the I/O-scheduling class and priority of a process." fullword ascii
      $s5 = " -P, --pgid <pgrp>...   act on already running processes in these groups" fullword ascii
      $s6 = " -p, --pid <pid>...     act on these already running processes" fullword ascii
      $s7 = "bad usage" fullword ascii
      $s8 = "ioprio_set failed" fullword ascii
      $s9 = " %1$s [options] -u <uid>..." fullword ascii
      $s10 = " %1$s [options] -p <pid>..." fullword ascii
      $s11 = "%s: prio %lu" fullword ascii
      $s12 = " -t, --ignore           ignore failures" fullword ascii
      $s13 = "invalid PID argument" fullword ascii
      $s14 = "best-effort" fullword ascii
      $s15 = "0ff174f252c83b9cbb8731120e1b151d5dd925.debug" fullword ascii
      $s16 = "invalid UID argument" fullword ascii
      $s17 = "invalid PGID argument" fullword ascii
      $s18 = "classdata" fullword ascii
      $s19 = "invalid class argument" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "ionice(1)" fullword ascii
      $s21 = "unknown scheduling class: '%s'" fullword ascii
      $s22 = " %1$s [options] -P <pgid>..." fullword ascii
      $s23 = "ignoring given class data for none class" fullword ascii
      $s24 = "ignoring given class data for idle class" fullword ascii
      $s25 = "invalid class data argument" fullword ascii
      $s26 = "+n:c:p:P:u:tVh" fullword ascii
      $s27 = "0ff174f252c83b9cbb8731120e1b151d5dd925" ascii
      $s28 = "%-24s%s" fullword ascii
      $s29 = "unknown prio class %d" fullword ascii
      $s30 = "realtime" fullword ascii /* Goodware String - occured 5 times */
      $s31 = "can handle only one of pid, pgid or uid at once" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule start_stop_daemon {
   strings:
      $s1 = "Program %s, %d process(es), refused to die." fullword ascii
      $s2 = "need at least one of --exec, --pid, --ppid, --pidfile, --user or --name" fullword ascii
      $s3 = "longer than %d characters, please use --exec instead of --name." fullword ascii
      $s4 = "  2 = with --retry, processes would not die" fullword ascii
      $s5 = "process in pidfile '%s'" fullword ascii
      $s6 = "process(es) owned by '%s'" fullword ascii
      $s7 = "  -u, --user <username|uid>     process owner to check" fullword ascii
      $s8 = "unable to set process scheduler" fullword ascii
      $s9 = "process scheduler priority greater than max" fullword ascii
      $s10 = "invalid process scheduler policy" fullword ascii
      $s11 = "process scheduler priority less than min" fullword ascii
      $s12 = "invalid process scheduler priority" fullword ascii
      $s13 = "this system is not able to track process names" fullword ascii
      $s14 = "--start needs --exec or --startas" fullword ascii
      $s15 = "%s:%s:%d:%s: internal error: " fullword ascii
      $s16 = "process with pid %d" fullword ascii
      $s17 = "process(es) with parent pid %d" fullword ascii
      $s18 = "  -g, --group <group|gid>       run process as this group" fullword ascii
      $s19 = "  -N, --nicelevel <incr>        add incr to the process' nice level" fullword ascii
      $s20 = "  -n, --name <process-name>     process name to check" fullword ascii
      $s21 = "gettimeofday failed" fullword ascii
      $s22 = "  -R, --retry <schedule>        check whether processes die, and retry" fullword ascii
      $s23 = "  -b, --background              force the process to detach" fullword ascii
      $s24 = "strndup(%s, %zu) failed" fullword ascii
      $s25 = "failed to kill %d: %s" fullword ascii
      $s26 = "nothing in /proc - not mounted?" fullword ascii
      $s27 = "                                  process" fullword ascii
      $s28 = "Usage: start-stop-daemon [<option>...] <command>" fullword ascii
      $s29 = "  -x, --exec <executable>       program to start/check if it is running" fullword ascii
      $s30 = "  -a, --startas <pathname>      program to start (default is <executable>)" fullword ascii
      $s31 = "The process scheduler <policy> can be one of:" fullword ascii
      $s32 = "No %s found running; none killed." fullword ascii
      $s33 = "user '%s' not found" fullword ascii
      $s34 = "-> Notification => ready for service." fullword ascii
      $s35 = "only one command can be specified" fullword ascii
      $s36 = "matching only on non-root pidfile %s is insecure" fullword ascii
      $s37 = "  -S, --start -- <argument>...  start a program and pass <arguments> to it" fullword ascii
      $s38 = " (as user %s[%d]" fullword ascii
      $s39 = "                                  process scheduler (default prio is 0)" fullword ascii
      $s40 = "program failed to initialize" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_bash {
   strings:
      $s1 = "      -x  keyseq:shell-command" fullword ascii
      $s2 = "vi-edit-and-execute-command" fullword ascii
      $s3 = "      -x  Print commands and their arguments as they are executed." fullword ascii
      $s4 = "      -n  Read commands but do not execute them." fullword ascii
      $s5 = "    Execute COMMAND, replacing this shell with the specified program." fullword ascii
      $s6 = "    Execute SHELL-BUILTIN with arguments ARGs without performing command" fullword ascii
      $s7 = "bind [-lpsvPSVX] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-command] [keyseq:readline-function o" ascii
      $s8 = "bind [-lpsvPSVX] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-command] [keyseq:readline-function o" ascii
      $s9 = "      -t  Exit after reading and executing one command." fullword ascii
      $s10 = "    Exits a login shell with exit status N.  Returns an error if not executed" fullword ascii
      $s11 = "    All file operators except -h and -L are acting on the target of a symbolic" fullword ascii
      $s12 = "execute_variable_command" fullword ascii
      $s13 = "execute_array_command" fullword ascii
      $s14 = "_rl_command_to_execute" fullword ascii
      $s15 = "    execute a disk command which has the same name as a shell builtin" fullword ascii
      $s16 = "    Execute PIPELINE and print a summary of the real time, user CPU time," fullword ascii
      $s17 = "execute_command_internal" fullword ascii
      $s18 = "echo_command_at_execute" fullword ascii
      $s19 = "      -v    print a description of COMMAND similar to the `type' builtin" fullword ascii
      $s20 = "    If the -p option is supplied, the process or job identifier of the job" fullword ascii
      $s21 = "    Execute COMMAND asynchronously, with the standard output and standard" fullword ascii
      $s22 = "    Read and execute commands from FILENAME in the current shell.  The" fullword ascii
      $s23 = "    executed commands.  If VALUE is supplied, assign VALUE before exporting." fullword ascii
      $s24 = "command_execution_string" fullword ascii
      $s25 = "    If the command cannot be executed, a non-interactive shell exits, unless" fullword ascii
      $s26 = "    runs the last command beginning with `cc' and typing `r' re-executes" fullword ascii
      $s27 = "-ilrsD or -c command or -O shopt_option" fullword ascii
      $s28 = "    last command executed within the function or script." fullword ascii
      $s29 = "${FCEDIT:-${EDITOR:-$(command -v editor || echo vi)}}" fullword ascii
      $s30 = "force the suspend, even if the shell is a login shell or job" fullword ascii
      $s31 = "    Returns success or status of executed command; non-zero if an error occurs." fullword ascii
      $s32 = "${FCEDIT:-${EDITOR:-$(command -v editor || echo ed)}}" fullword ascii
      $s33 = "executing_command_builtin" fullword ascii
      $s34 = "fc -e \"${VISUAL:-${EDITOR:-$(command -v editor || echo emacs)}}\"" fullword ascii
      $s35 = "    Returns the status of the last command executed in FILENAME; fails if" fullword ascii
      $s36 = "    ARG is a command to be read and executed when the shell receives the" fullword ascii
      $s37 = "fc -e \"${VISUAL:-${EDITOR:-$(command -v editor || echo vi)}}\"" fullword ascii
      $s38 = "    Enables and disables builtin shell commands.  Disabling allows you to" fullword ascii
      $s39 = "r readline-command]" fullword ascii
      $s40 = "    Create a shell function named NAME.  When invoked as a simple command," fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 4000KB and
      8 of them
}

rule false_negative_bins_dpkg {
   strings:
      $s1 = "  --status-logger=<command>  Send status change updates to <command>'s stdin." fullword ascii
      $s2 = "process_archive conffile '%s' in package %s - conff ?" fullword ascii
      $s3 = "post_script_tasks - ensure_diversions" fullword ascii
      $s4 = "process_archive conffile '%s' in package %s - conff ? not '%s'" fullword ascii
      $s5 = "process_archive tmp.ci script/file '%s' contains dot" fullword ascii
      $s6 = "process_archive tmp.ci script/file '%s' is control" fullword ascii
      $s7 = "process_archive tmp.ci script/file '%s' installed as '%s'" fullword ascii
      $s8 = "process queue pkg %s queue.len %d progress %d, try %d" fullword ascii
      $s9 = "process_archive: old conff %s is same as new conff %s, copying hash" fullword ascii
      $s10 = "post_script_tasks - trig_incorporate" fullword ascii
      $s11 = "dependency problems - leaving triggers unprocessed" fullword ascii
      $s12 = "process_archive conffile '%s' package=%s %s hash=%s" fullword ascii
      $s13 = "error processing archive %s (--%s):" fullword ascii
      $s14 = "error processing package %s (--%s):" fullword ascii
      $s15 = "process_archive: old conff %s is same as new conff %s but latter already has hash" fullword ascii
      $s16 = "subprocess %s returned error exit status %d" fullword ascii
      $s17 = "there is no script in the new version of the package - giving up" fullword ascii
      $s18 = "process_archive conffile '%s' no package, no hash" fullword ascii
      $s19 = "wait for %s subprocess failed" fullword ascii
      $s20 = "process_archive: not removing %s, since it matches %s" fullword ascii
      $s21 = "dependency problems prevent processing triggers for %s:" fullword ascii
      $s22 = "processing: %s: %s" fullword ascii
      $s23 = "  --compare-versions <a> <op> <b>  Compare version numbers - see below." fullword ascii
      $s24 = "Comparison operators for --compare-versions are:" fullword ascii
      $s25 = "error executing hook '%s', exit code %d" fullword ascii
      $s26 = "%s subprocess failed with wait status code %d" fullword ascii
      $s27 = "%s subprocess was killed by signal (%s)%s" fullword ascii
      $s28 = "  Package %s which provides %s awaits trigger processing." fullword ascii
      $s29 = "unable to get file descriptor for directory '%s'" fullword ascii
      $s30 = "process_archive oldversionstatus=%s" fullword ascii
      $s31 = "%s subprocess returned error exit status %d" fullword ascii
      $s32 = "unknown system user '%s' in statoverride file; the system user got removed" fullword ascii
      $s33 = "package %s was on hold, processing it anyway as you requested" fullword ascii
      $s34 = "process_archive not overwriting any '%s' (overriding, '%s')" fullword ascii
      $s35 = "process_archive looking for overwriting '%s'" fullword ascii
      $s36 = "Process even packages with wrong versions" fullword ascii
      $s37 = "Errors were encountered while processing:" fullword ascii
      $s38 = "process_archive info installed %s as %s" fullword ascii
      $s39 = "Package %s listed more than once, only processing once." fullword ascii
      $s40 = "process_archive looking for overwriting '%s' (overridden by %s)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 900KB and
      8 of them
}

rule false_negative_bins_mount {
   strings:
      $s1 = "%s: parse error at line %d -- ignored" fullword ascii
      $s2 = " %1$s <operation> <mountpoint> [<target>]" fullword ascii
      $s3 = "failed to set target namespace to %s" fullword ascii
      $s4 = "mnt_context_set_target_ns" fullword ascii
      $s5 = " %1$s [options] [--source] <source> | [--target] <directory>" fullword ascii
      $s6 = "mnt_context_helper_executed" fullword ascii
      $s7 = "mnt_context_set_target" fullword ascii
      $s8 = "mnt_context_set_target_prefix" fullword ascii
      $s9 = "mnt_context_get_target" fullword ascii
      $s10 = "target-prefix" fullword ascii
      $s11 = "getfilecon" fullword ascii
      $s12 = "     --target-prefix <path>" fullword ascii
      $s13 = "     --target <target>   explicitly specifies mountpoint" fullword ascii
      $s14 = " %1$s -a [options]" fullword ascii
      $s15 = "failed to read mtab" fullword ascii
      $s16 = "mnt_get_library_version" fullword ascii
      $s17 = "drop permissions failed" fullword ascii
      $s18 = " -O, --test-opts <list>  limit the set of filesystems (use with -a)" fullword ascii
      $s19 = "mnt_fs_set_target" fullword ascii
      $s20 = "mnt_fs_get_target" fullword ascii
      $s21 = " -w, --rw, --read-write  mount the filesystem read-write (default)" fullword ascii
      $s22 = " -r, --read-only         mount the filesystem read-only (same as -o ro)" fullword ascii
      $s23 = "mount: %s does not contain SELinux labels." fullword ascii
      $s24 = "failed to append option '%s'" fullword ascii
      $s25 = " -B, --bind              mount a subtree somewhere else (same as -o bind)" fullword ascii
      $s26 = "make-runbindable" fullword ascii
      $s27 = "%s: %s moved to %s." fullword ascii
      $s28 = "%s: %s bound on %s." fullword ascii
      $s29 = "%s: failed to parse" fullword ascii
      $s30 = "%s: %s mounted on %s." fullword ascii
      $s31 = "%s: %s propagation flags changed." fullword ascii
      $s32 = "mnt_optstr_get_option" fullword ascii
      $s33 = "mnt_context_get_mtab" fullword ascii
      $s34 = "failed to set options pattern" fullword ascii
      $s35 = "mnt_fs_get_options" fullword ascii
      $s36 = "mnt_context_get_excode" fullword ascii
      $s37 = "mnt_context_get_mflags" fullword ascii
      $s38 = "mnt_context_get_status" fullword ascii
      $s39 = "mnt_context_get_fs" fullword ascii
      $s40 = "mnt_context_enable_fake" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_wall {
   strings:
      $s1 = "will not read %s - use stdin." fullword ascii
      $s2 = "xgetgrnam" fullword ascii
      $s3 = "xgetpwuid" fullword ascii
      $s4 = "xgetpwnam" fullword ascii
      $s5 = "Write a message to all users." fullword ascii
      $s6 = "getgrouplist found more groups than sysconf allows" fullword ascii
      $s7 = "cannot get passwd uid" fullword ascii
      $s8 = "%s: BAD ERROR, message is far too long" fullword ascii
      $s9 = " -t, --timeout <timeout> write timeout in seconds" fullword ascii
      $s10 = "nobanner" fullword ascii
      $s11 = "internal error: too many iov's" fullword ascii
      $s12 = "--nobanner is available only for root" fullword ascii
      $s13 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/bsdutils.debug" fullword ascii
      $s14 = " %s [options] [<file> | <message>]" fullword ascii
      $s15 = "%s: unknown gid" fullword ascii
      $s16 = "invalid timeout argument" fullword ascii
      $s17 = "invalid group argument" fullword ascii
      $s18 = " -n, --nobanner          do not print banner, works only for root" fullword ascii
      $s19 = "excessively long line arg" fullword ascii
      $s20 = "grpbuf" fullword ascii
      $s21 = "pwdbuf" fullword ascii
      $s22 = "username" fullword ascii /* Goodware String - occured 262 times */
      $s23 = "cannot allocate %zu bytes" fullword ascii /* Goodware String - occured 1 times */
      $s24 = "lib/pwdutils.c" fullword ascii
      $s25 = "invalid timeout argument: %s" fullword ascii
      $s26 = "wall(1)" fullword ascii
      $s27 = "6335c8de043a8743e79716839aa2a4c819ac30d.debug" fullword ascii
      $s28 = "fork: %m" fullword ascii
      $s29 = "<someone>" fullword ascii
      $s30 = "open_memstream" fullword ascii /* Goodware String - occured 2 times */
      $s31 = "somewhere" fullword ascii /* Goodware String - occured 2 times */
      $s32 = "write failed: %s" fullword ascii /* Goodware String - occured 2 times */
      $s33 = " -g, --group <group>     only send message to group" fullword ascii
      $s34 = "Broadcast message from %s@%s (%s) (%s):" fullword ascii
      $s35 = "cannot duplicate string" fullword ascii
      $s36 = "\\%3hho" fullword ascii
      $s37 = "%-25s%s" fullword ascii
      $s38 = "getgrouplist" fullword ascii /* Goodware String - occured 4 times */
      $s39 = "6335c8de043a8743e79716839aa2a4c819ac30d" ascii
      $s40 = "t>yqh9" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_dmesg {
   strings:
      $s1 = "%d: %s: don't print memory addresses (SUID executable)." fullword ascii
      $s2 = "read kernel buffer failed" fullword ascii
      $s3 = "userspace" fullword ascii
      $s4 = "clear kernel buffer failed" fullword ascii
      $s5 = "klogctl failed" fullword ascii
      $s6 = "lightmagenta" fullword ascii
      $s7 = "klogctl" fullword ascii
      $s8 = " -F, --file <file>           use the file instead of the kernel log buffer" fullword ascii
      $s9 = "terminal is ready (supports %d colors)" fullword ascii
      $s10 = "Supported log facilities:" fullword ascii
      $s11 = "--raw can be used together with --level or --facility only when reading messages from /dev/kmsg" fullword ascii
      $s12 = "Supported log levels (priorities):" fullword ascii
      $s13 = "setting '%s' from %d -to-> %d" fullword ascii
      $s14 = " -u, --userspace             display userspace messages" fullword ascii
      $s15 = "messages generated internally by syslogd" fullword ascii
      $s16 = "kernel messages" fullword ascii
      $s17 = "failed to set the %s environment variable" fullword ascii
      $s18 = "reading dir: '%s'" fullword ascii
      $s19 = "failed to parse facility '%s'" fullword ascii
      $s20 = "waitpid failed (%s)" fullword ascii
      $s21 = "reading file '%s'" fullword ascii
      $s22 = "security/authorization messages (private)" fullword ascii
      $s23 = "failed to parse level '%s'" fullword ascii
      $s24 = "stat of %s failed" fullword ascii
      $s25 = "item '%s': score=%d [cur: %d, name(%zu): %s, term(%zu): %s]" fullword ascii
      $s26 = "system daemons" fullword ascii
      $s27 = "line printer subsystem" fullword ascii
      $s28 = " -P, --nopager               do not pipe output into a pager" fullword ascii
      $s29 = "Display or control the kernel ring buffer." fullword ascii
      $s30 = " %7s - %s" fullword ascii
      $s31 = "network news subsystem" fullword ascii
      $s32 = "error conditions" fullword ascii
      $s33 = "(out - *seq) <= len" fullword ascii
      $s34 = "mail system" fullword ascii
      $s35 = "system is unusable" fullword ascii
      $s36 = "unsupported color mode" fullword ascii
      $s37 = "--show-delta is ignored when used together with iso8601 time format" fullword ascii
      $s38 = " -L, --color[=<when>]        colorize messages (%s, %s or %s)" fullword ascii
      $s39 = "bad usage" fullword ascii
      $s40 = "lightred" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule false_negative_bins_script {
   strings:
      $s1 = " -c, --command <command>       run command rather than interactive shell" fullword ascii
      $s2 = "Script done on %s [COMMAND_EXIT_CODE=\"%d\"]" fullword ascii
      $s3 = "%d: %s: don't print memory addresses (SUID executable)." fullword ascii
      $s4 = " stdin --> master trying %zu bytes" fullword ascii
      $s5 = " stdin --> master %zd bytes queued" fullword ascii
      $s6 = "COMMAND=\"%s\"" fullword ascii
      $s7 = "unsupported logging format: '%s'" fullword ascii
      $s8 = "log->format == SCRIPT_FMT_TIMING_MULTI" fullword ascii
      $s9 = "%*s<not executed on terminal>" fullword ascii
      $s10 = " -e, --return                  return exit code of the child process" fullword ascii
      $s11 = "Script done on %s [<%s>]" fullword ascii
      $s12 = "cannot create child process" fullword ascii
      $s13 = "Make a typescript of a terminal session." fullword ascii
      $s14 = " master --> stdout %zd bytes" fullword ascii
      $s15 = "Script started on %s [" fullword ascii
      $s16 = ", output log file is '%s'" fullword ascii
      $s17 = " child stop by SIGSTOP -- stop parent too" fullword ascii
      $s18 = ", input log file is '%s'" fullword ascii
      $s19 = "stop logging" fullword ascii
      $s20 = "  log timing info" fullword ascii
      $s21 = " -B, --log-io <file>           log stdin and stdout to file" fullword ascii
      $s22 = " -I, --log-in <file>           log stdin to file" fullword ascii
      $s23 = "Script done." fullword ascii
      $s24 = "SCRIPT_DEBUG" fullword ascii
      $s25 = "term-utils/script.c" fullword ascii
      $s26 = "unssuported echo mode: '%s'" fullword ascii
      $s27 = "Script started" fullword ascii
      $s28 = "Session terminated, killing shell..." fullword ascii
      $s29 = "Script terminated, max output files size %lu exceeded." fullword ascii
      $s30 = "script(1)" fullword ascii
      $s31 = "pty setup done [master=%d, slave=%d, rc=%d]" fullword ascii
      $s32 = "poll() done [signal=%d, rc=%d]" fullword ascii
      $s33 = "leaving poll() loop [timeout=%d, rc=%d]" fullword ascii
      $s34 = " get signal SIGCHLD" fullword ascii
      $s35 = " get signal SIGUSR1" fullword ascii
      $s36 = " get signal SIGWINCH" fullword ascii
      $s37 = " get signal SIG{TERM,INT,QUIT}" fullword ascii
      $s38 = "failed to parse output limit size" fullword ascii
      $s39 = "TIMING_LOG" fullword ascii
      $s40 = "ul_pty_get_delivered_signal" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_su {
   strings:
      $x1 = "options --{shell,fast,command,session-command,login} and --user are mutually exclusive" fullword ascii
      $s2 = "starting shell [shell=%s, command=\"%s\"%s%s]" fullword ascii
      $s3 = "Run <command> with the effective user ID and group ID of <user>.  If -u is" fullword ascii
      $s4 = " --session-command <command>     pass a single command to the shell with -c" fullword ascii
      $s5 = " -c, --command <command>         pass a single command to the shell with -c" fullword ascii
      $s6 = " %1$s [options] -u <user> [[--] <command>]" fullword ascii
      $s7 = "%d: %s: don't print memory addresses (SUID executable)." fullword ascii
      $s8 = "not given, fall back to su(1)-compatible semantics and execute standard shell." fullword ascii
      $s9 = "session-command" fullword ascii
      $s10 = " -, -l, --login                  make the shell a login shell" fullword ascii
      $s11 = "ignoring --preserve-environment, it's mutually exclusive with --login" fullword ascii
      $s12 = " (core dumped)" fullword ascii
      $s13 = " -f, --fast                      pass -f to the shell (for csh or tcsh)" fullword ascii
      $s14 = "A mere - implies -l.  If <user> is not given, root is assumed." fullword ascii
      $s15 = "hush login status: restore original IDs failed" fullword ascii
      $s16 = "login-utils/su-common.c" fullword ascii
      $s17 = "loading logindefs" fullword ascii
      $s18 = " stdin --> master trying %zu bytes" fullword ascii
      $s19 = " stdin --> master %zd bytes queued" fullword ascii
      $s20 = "%s is restricted shell (not in /etc/shells)" fullword ascii
      $s21 = "/etc/login.defs" fullword ascii
      $s22 = "HUSHLOGIN_FILE" fullword ascii
      $s23 = " session resumed -- continue" fullword ascii
      $s24 = "may not be used by non-root users" fullword ascii
      $s25 = "failed to establish user credentials: %s" fullword ascii
      $s26 = " child got SIGSTOP -- stop all session" fullword ascii
      $s27 = "/etc/hushlogins" fullword ascii
      $s28 = "btmp logging" fullword ascii
      $s29 = " login" fullword ascii
      $s30 = "no command was specified" fullword ascii
      $s31 = "xgetgrnam" fullword ascii
      $s32 = "xgetpwuid" fullword ascii
      $s33 = "xgetpwnam" fullword ascii
      $s34 = "cannot create child process" fullword ascii
      $s35 = " master --> stdout %zd bytes" fullword ascii
      $s36 = "FAILED RUNUSER " fullword ascii
      $s37 = "The options -c, -f, -l, and -s are mutually exclusive with -u." fullword ascii
      $s38 = "syslog logging" fullword ascii
      $s39 = "failed to set the %s environment variable" fullword ascii
      $s40 = "Session terminated, killing shell..." fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule false_negative_bins_python3 {
   strings:
      $s1 = "Return True if the process returning status was dumped to a core file." fullword ascii
      $s2 = "77777777777777777777777777777777" wide /* reversed goodware string '77777777777777777777777777777777' */ /* hex encoded string 'wwwwwwwwwwwwwwww' */
      $s3 = "777777777777777777777777777777" wide /* reversed goodware string '777777777777777777777777777777' */ /* hex encoded string 'wwwwwwwwwwwwwww' */
      $s4 = "7777777777777777777777" wide /* reversed goodware string '7777777777777777777777' */ /* hex encoded string 'wwwwwwwwwww' */
      $s5 = "777777777777777777777777777777777777777777777777777777" wide /* reversed goodware string '777777777777777777777777777777777777777777777777777777' */ /* hex encoded string 'wwwwwwwwwwwwwwwwwwwwwwwwwww' */
      $s6 = "777777777777" wide /* reversed goodware string '777777777777' */ /* hex encoded string 'wwwwww' */
      $s7 = "777777777777777777" wide /* reversed goodware string '777777777777777777' */ /* hex encoded string 'wwwwwwwww' */
      $s8 = "7777777777777777777777777777777777777777777777" wide /* reversed goodware string '7777777777777777777777777777777777777777777777' */ /* hex encoded string 'wwwwwwwwwwwwwwwwwwwwwww' */
      $s9 = "77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777" wide /* reversed goodware string '777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777' */ /* hex encoded string 'wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww' */
      $s10 = "7777777777777777777777777777" wide /* reversed goodware string '7777777777777777777777777777' */ /* hex encoded string 'wwwwwwwwwwwwww' */
      $s11 = "77777777777777" wide /* reversed goodware string '77777777777777' */ /* hex encoded string 'wwwwwww' */
      $s12 = "77777777777777777777" wide /* reversed goodware string '77777777777777777777' */ /* hex encoded string 'wwwwwwwwww' */
      $s13 = "333333333333333333333333333333333333333333" wide /* reversed goodware string '333333333333333333333333333333333333333333' */ /* hex encoded string '333333333333333333333' */
      $s14 = "getnameinfo(sockaddr, flags) --> (host, port)" fullword ascii
      $s15 = "Execute the command in a subshell." fullword ascii
      $s16 = "Execute the program specified by path in a new process." fullword ascii
      $s17 = "  gr_passwd - group password (encrypted); often empty" fullword ascii
      $s18 = "  - a text string encoded using the specified encoding" fullword ascii
      $s19 = "FileLoader.get_resource_reader" fullword ascii
      $s20 = "NamespaceLoader.get_resource_reader" fullword ascii
      $s21 = "Get the scheduling policy for the process identified by pid." fullword ascii
      $s22 = "LazyLoader.exec_module" fullword ascii
      $s23 = "If an error occurs in the child process before the exec, it is" fullword ascii
      $s24 = "ExtensionFileLoader.exec_module" fullword ascii
      $s25 = "Process time for profiling: sum of the kernel and user-space CPU time." fullword ascii
      $s26 = "NamespaceLoader.exec_module" fullword ascii
      $s27 = "    the target file descriptor of the operation" fullword ascii
      $s28 = "decoded or encoded with. It defaults to locale.getencoding()." fullword ascii
      $s29 = "FrozenImporter.exec_module" fullword ascii
      $s30 = "dumps() -- marshal value as a bytes object" fullword ascii
      $s31 = "decodedbytes" fullword ascii
      $s32 = "BuiltinImporter.exec_module" fullword ascii
      $s33 = "register(signum, file=sys.stderr, all_threads=True, chain=False): register a handler for the signal 'signum': dump the traceback" ascii
      $s34 = "FileLoader.get_data" fullword ascii
      $s35 = "that will be decoded using the given encoding and error handler." fullword ascii
      $s36 = "gethostbyname_ex(host) -> (name, aliaslist, addresslist)" fullword ascii
      $s37 = "getusersitepackages" fullword ascii
      $s38 = "SourcelessFileLoader.get_code" fullword ascii
      $s39 = "Return the round-robin quantum for the process identified by pid, in seconds." fullword ascii
      $s40 = "NamespaceLoader.get_source" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 20000KB and
      8 of them
}

rule false_negative_bins_chown {
   strings:
      $s1 = "  %s root:staff /u  Likewise, but also change its group to \"staff\"." fullword ascii
      $s2 = "to login group if implied by a ':' following a symbolic OWNER." fullword ascii
      $s3 = "      --preserve-root    fail to operate recursively on '/'" fullword ascii
      $s4 = "  -v, --verbose          output a diagnostic for every file processed" fullword ascii
      $s5 = "  %s -hR root /u    Change the owner of /u and subfiles to \"root\"." fullword ascii
      $s6 = "  %s root /u        Change the owner of /u to \"root\"." fullword ascii
      $s7 = "  -H                     if a command line argument is a symbolic link" fullword ascii
      $s8 = "  -f, --silent, --quiet  suppress most error messages" fullword ascii
      $s9 = "  -P                     do not traverse any symbolic links (default)" fullword ascii
      $s10 = "  -L                     traverse every symbolic link to a directory" fullword ascii
      $s11 = "  -R, --recursive        operate on files and directories recursively" fullword ascii
      $s12 = "      --no-preserve-root  do not treat '/' specially (the default)" fullword ascii
      $s13 = "  -c, --changes          like verbose but report only when a change is made" fullword ascii
      $s14 = "  or:  %s [OPTION]... --reference=RFILE FILE..." fullword ascii
      $s15 = "__openat_2" fullword ascii
      $s16 = "warning: '.' should be ':'" fullword ascii
      $s17 = "c3267c77e8ab495e750bd3ac630400d379908c.debug" fullword ascii
      $s18 = "state->magic == 9827862" fullword ascii
      $s19 = "                         to a directory, traverse it" fullword ascii
      $s20 = "lib/cycle-check.c" fullword ascii
      $s21 = "invalid spec" fullword ascii /* Goodware String - occured 2 times */
      $s22 = "      --dereference      affect the referent of each symbolic link (this is" fullword ascii
      $s23 = "  -h, --no-dereference   affect symbolic links instead of any referenced file" fullword ascii
      $s24 = "      --from=CURRENT_OWNER:CURRENT_GROUP" fullword ascii
      $s25 = "OWNER and GROUP may be numeric as well as symbolic." fullword ascii /* Goodware String - occured 2 times */
      $s26 = "Usage: %s [OPTION]... [OWNER][:[GROUP]] FILE..." fullword ascii /* Goodware String - occured 2 times */
      $s27 = "M9l$ t" fullword ascii /* Goodware String - occured 2 times */
      $s28 = "failed to change group of %s from %s to %s" fullword ascii /* Goodware String - occured 2 times */
      $s29 = "      --reference=RFILE  use RFILE's owner and group rather than" fullword ascii
      $s30 = "failed to change ownership of %s from %s to %s" fullword ascii /* Goodware String - occured 2 times */
      $s31 = "With --reference, change the owner and group of each FILE to those of RFILE." fullword ascii /* Goodware String - occured 2 times */
      $s32 = "changed group of %s from %s to %s" fullword ascii /* Goodware String - occured 2 times */
      $s33 = "changed ownership of %s from %s to %s" fullword ascii /* Goodware String - occured 2 times */
      $s34 = "Owner is unchanged if missing.  Group is unchanged if missing, but changed" fullword ascii /* Goodware String - occured 3 times */
      $s35 = "Change the owner and/or group of each FILE to OWNER and/or GROUP." fullword ascii /* Goodware String - occured 3 times */
      $s36 = "invalid user" fullword ascii /* Goodware String - occured 4 times */
      $s37 = "invalid group" fullword ascii /* Goodware String - occured 4 times */
      $s38 = "L$8H9u0tFM" fullword ascii
      $s39 = "cannot dereference %s" fullword ascii /* Goodware String - occured 4 times */
      $s40 = "I9T$8s/H" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_tar {
   strings:
      $s1 = "%s: directory is on a different filesystem; not dumped" fullword ascii
      $s2 = "print total bytes after processing the archive; with an argument - print total bytes when this SIGNAL is delivered; Allowed sign" ascii
      $s3 = "preserve access times on dumped files, either by restoring the times after reading (METHOD='replace'; default) or by not setting" ascii
      $s4 = "Refusing to read archive contents from terminal (missing -f option?)" fullword ascii
      $s5 = "lgetxattrat" fullword ascii
      $s6 = "Refusing to write archive contents to terminal (missing -f option?)" fullword ascii
      $s7 = "Try '%s --help' or '%s --usage' for more information." fullword ascii
      $s8 = "mmands --delete, --diff, --extract or --list and when a list of files is given either on the command line or via the -T option; " ascii
      $s9 = "Unknown quoting style '%s'. Try '%s --quoting-style=help' to get a list." fullword ascii
      $s10 = "Ignoring unknown extended header keyword '%s'" fullword ascii
      $s11 = "failed to assert availability of the standard file descriptors" fullword ascii
      $s12 = "process only the NUMBERth occurrence of each file in the archive; this option is valid only in conjunction with one of the subco" ascii
      $s13 = "Malformed dumpdir: 'T' not preceded by 'R'" fullword ascii
      $s14 = "%s: option '%s%s' doesn't allow an argument" fullword ascii
      $s15 = "%s: option '%s%s' is ambiguous; possibilities:" fullword ascii
      $s16 = "%s: unrecognized option '%s%s'" fullword ascii
      $s17 = "%s: option '%s%s' is ambiguous" fullword ascii
      $s18 = "%s: option '%s%s' requires an argument" fullword ascii
      $s19 = "lgetfilecon" fullword ascii
      $s20 = "fgetfilecon" fullword ascii
      $s21 = "setxattrat" fullword ascii
      $s22 = "lgetfileconat" fullword ascii
      $s23 = "llistxattrat" fullword ascii
      $s24 = "error: %s:%d" fullword ascii
      $s25 = "%{%Y-%m-%d %H:%M:%S}t: %ds, %{read,wrote}T%*" fullword ascii
      $s26 = "%s: file list requested from %s already read from %s" fullword ascii
      $s27 = "globbing error" fullword ascii
      $s28 = "slash - dir < 4096" fullword ascii
      $s29 = "errors reading map file" fullword ascii
      $s30 = "'@timespec' - always UTC" fullword ascii
      $s31 = "Options '-Aru' are incompatible with '-f -'" fullword ascii
      $s32 = "error: invalid hour %ld%s" fullword ascii
      $s33 = "Cannot redirect files for remote shell" fullword ascii
      $s34 = "Options '-[0-7][lmh]' not supported by *this* tar" fullword ascii
      $s35 = "invalid wordsplit usage" fullword ascii
      $s36 = "  tar -cf archive.tar foo bar  # Create archive.tar from files foo and bar." fullword ascii
      $s37 = " isdst=%d%s" fullword ascii
      $s38 = " y or newline  Continue operation" fullword ascii
      $s39 = "XXA NULL argv[0] was passed through an exec system call." fullword ascii
      $s40 = "-T reads null-terminated names; implies --verbatim-files-from" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule false_negative_bins_rev {
   strings:
      $s1 = "Usage: %s [options] [file ...]" fullword ascii
      $s2 = "cannot allocate %zu bytes" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "db6d519a837763fe2ee4baa2257cc0e583b0c5.debug" fullword ascii
      $s4 = "Reverse lines characterwise." fullword ascii
      $s5 = "%s: %ju" fullword ascii
      $s6 = "%-16s%s" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "db6d519a837763fe2ee4baa2257cc0e583b0c5" ascii
      $s8 = "rev(1)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 40KB and
      all of them
}

rule false_negative_bins_more {
   strings:
      $s1 = "******** %s: Not a text file ********" fullword ascii
      $s2 = "*** %s: directory ***" fullword ascii
      $s3 = "!<cmd> or :!<cmd>       Execute <cmd> in a subshell" fullword ascii
      $s4 = "Most commands optionally preceded by integer argument k.  Defaults in brackets." fullword ascii
      $s5 = "No previous command to substitute for" fullword ascii
      $s6 = "drop permissions failed" fullword ascii
      $s7 = "stat of %s failed" fullword ascii
      $s8 = "failed to parse number" fullword ascii
      $s9 = "argument error" fullword ascii
      $s10 = "bad usage" fullword ascii
      $s11 = " -n, --lines <number>  the number of lines per screenful" fullword ascii
      $s12 = "signalfd" fullword ascii
      $s13 = "(Next file: %s)" fullword ascii
      $s14 = ".                       Repeat previous command" fullword ascii
      $s15 = "\"%s\" line %d" fullword ascii
      $s16 = "...skipping %d line" fullword ascii
      $s17 = "...skipping %d lines" fullword ascii
      $s18 = "cannot allocate %zu bytes" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "NCURSES6_TINFO_5.0.19991023" fullword ascii
      $s20 = "libtinfo.so.6" fullword ascii
      $s21 = "./include/xalloc.h" fullword ascii
      $s22 = "[Not a file] line %d" fullword ascii
      $s23 = "exit-on-eof" fullword ascii
      $s24 = "cur_term" fullword ascii /* Goodware String - occured 1 times */
      $s25 = "text-utils/more.c" fullword ascii
      $s26 = "clean-print" fullword ascii
      $s27 = "A file perusal filter for CRT viewing." fullword ascii
      $s28 = "MORE environment variable" fullword ascii
      $s29 = "sz == sizeof(info)" fullword ascii
      $s30 = "/usr/bin/vi" fullword ascii
      $s31 = "s                       Skip forward k lines of text [1]" fullword ascii
      $s32 = "[Press space to continue, 'q' to quit.]" fullword ascii
      $s33 = "print-over" fullword ascii
      $s34 = "dflcpsun:eVh" fullword ascii
      $s35 = "f                       Skip forward k screenfuls of text [1]" fullword ascii
      $s36 = " -f, --logical         count logical rather than screen lines" fullword ascii
      $s37 = "[Press 'h' for instructions.]" fullword ascii
      $s38 = "exec failed" fullword ascii /* Goodware String - occured 1 times */
      $s39 = "more(1)" fullword ascii
      $s40 = "more_poll" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_nsenter {
   strings:
      $s1 = " -t, --target <pid>     target process to get namespaces from" fullword ascii
      $s2 = "no target PID specified for --follow-context" fullword ascii
      $s3 = "failed to set exec context to '%s'" fullword ascii
      $s4 = "no target PID specified for --all" fullword ascii
      $s5 = "failed to get %d SELinux context" fullword ascii
      $s6 = "setexeccon" fullword ascii
      $s7 = " -Z, --follow-context   set SELinux context according to --target PID" fullword ascii
      $s8 = "change directory by working directory file descriptor failed" fullword ascii
      $s9 = "Run a program with namespaces of other processes." fullword ascii
      $s10 = "change directory by root file descriptor failed" fullword ascii
      $s11 = "neither filename nor target pid supplied for %s" fullword ascii
      $s12 = "getpidcon" fullword ascii
      $s13 = "chroot failed" fullword ascii
      $s14 = " -F, --no-fork          do not fork before exec'ing <program>" fullword ascii
      $s15 = "stat of %s failed" fullword ascii
      $s16 = "reassociate to namespace '%s' failed" fullword ascii
      $s17 = "failed to parse uid" fullword ascii
      $s18 = "setuid failed" fullword ascii
      $s19 = "setgroups failed" fullword ascii
      $s20 = "failed to parse gid" fullword ascii
      $s21 = "setgid failed" fullword ascii
      $s22 = "failed to parse pid" fullword ascii
      $s23 = "preserve-credentials" fullword ascii
      $s24 = " -C, --cgroup[=<file>]  enter cgroup namespace" fullword ascii
      $s25 = " -u, --uts[=<file>]     enter UTS namespace (hostname etc)" fullword ascii
      $s26 = "     --preserve-credentials do not touch uids or gids" fullword ascii
      $s27 = "%s: mutually exclusive arguments:" fullword ascii
      $s28 = " -U, --user[=<file>]    enter user namespace" fullword ascii
      $s29 = " -r, --root[=<dir>]     set the root directory" fullword ascii
      $s30 = " -i, --ipc[=<file>]     enter System V IPC namespace" fullword ascii
      $s31 = "target" fullword ascii /* Goodware String - occured 880 times */
      $s32 = "cannot allocate %zu bytes" fullword ascii /* Goodware String - occured 1 times */
      $s33 = "__xpg_basename" fullword ascii
      $s34 = "/proc/%u/%s" fullword ascii
      $s35 = "ns/user" fullword ascii
      $s36 = "nsfile->nstype" fullword ascii
      $s37 = "follow-context" fullword ascii
      $s38 = "+ahVt:m::u::i::n::p::C::U::T::S:G:r::w::W:FZ" fullword ascii
      $s39 = "sys-utils/nsenter.c" fullword ascii
      $s40 = "open_namespace_fd" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_as {
   strings:
      $s1 = "  -f                      skip whitespace and comment preprocessing" fullword ascii
      $s2 = "symbol type \"%s\" is supported only by GNU and FreeBSD targets" fullword ascii
      $s3 = "symbol type \"%s\" is supported only by GNU targets" fullword ascii
      $s4 = "symbol type \"%s\" is not supported by MIPS targets" fullword ascii
      $s5 = ".cfi_fde_data is not supported for this target" fullword ascii
      $s6 = ".cfi_personality_id is not supported for this target" fullword ascii
      $s7 = "%s section is supported only by GNU and FreeBSD targets" fullword ascii
      $s8 = "invalid attempt to declare external version name as default in symbol `%s'" fullword ascii
      $s9 = ".sframe not supported for target" fullword ascii
      $s10 = ".cfi_inline_lsda is not supported for this target" fullword ascii
      $s11 = "jump target out of range" fullword ascii
      $s12 = "noexecstack" fullword ascii
      $s13 = "  -moperand-check=[none|error|warning] (default: warning)" fullword ascii
      $s14 = "  --dump-config           display how the assembler is configured and then exit" fullword ascii
      $s15 = "execinstr" fullword ascii
      $s16 = "negative count for %s - ignored" fullword ascii
      $s17 = "bfd_target_list" fullword ascii
      $s18 = "Invalid --gdwarf-cie-version `%s'" fullword ascii
      $s19 = "Attempt to purge non-existing macro `%s'" fullword ascii
      $s20 = "Invalid --elf-stt-common= option: `%s'" fullword ascii
      $s21 = "attempt to fill section `%s' with non-zero value" fullword ascii
      $s22 = "file table slot %u is already occupied by a different file (%s%s%s vs %s%s%s)" fullword ascii
      $s23 = "attempt to .org/.space/.nops backwards? (%ld)" fullword ascii
      $s24 = "attempt to store float in section `%s'" fullword ascii
      $s25 = "`%s%c' is %s supported in 64-bit mode" fullword ascii
      $s26 = "Invalid --compress-debug-sections option: `%s'" fullword ascii
      $s27 = "attempt to store non-empty string in section `%s'" fullword ascii
      $s28 = ".largecomm supported only in 64bit mode, producing .comm" fullword ascii
      $s29 = "attempt to store non-zero value in section `%s'" fullword ascii
      $s30 = "%s:%u: add %d%s at 0x%llx to align %s within %d-byte boundary" fullword ascii
      $s31 = "%s:%u: add additional %d%s at 0x%llx to align %s within %d-byte boundary" fullword ascii
      $s32 = "%s:%u: add %d%s-byte nop at 0x%llx to align %s within %d-byte boundary" fullword ascii
      $s33 = "vpternlogd" fullword ascii
      $s34 = "vgetexpph" fullword ascii
      $s35 = "  --target-help           show target specific options" fullword ascii
      $s36 = "vgetmantsd" fullword ascii
      $s37 = "vgetmantph" fullword ascii
      $s38 = "vgetexpps" fullword ascii
      $s39 = "vpternlogq" fullword ascii
      $s40 = "attempt to store float in absolute section" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and
      8 of them
}

rule false_negative_bins_gcc {
   strings:
      $x1 = " %{pg:%{fomit-frame-pointer:%e-pg and -fomit-frame-pointer are incompatible}} %{!S:%{!c:%e-c or -S required for Ada}} gnat1 %{I*" ascii
      $x2 = "  gm2lcc %{fshared} %{fpic} %{fPIC} %{B*} %{L*} %{ftarget-ar=*}           %{ftarget-ranlib=*}           %{fobject-path=*} %{v} -" ascii
      $x3 = "   %{save-temps*:%b.ii} %{!save-temps*:%g.ii}}  %{!save-temps*:%{!no-integrated-cpp:%(cpp_unique_options)}}  %{fmodules-ts:-fmod" ascii
      $x4 = "../src/configure -v --with-pkgversion='Debian 12.2.0-14' --with-bugurl=file:///usr/share/doc/gcc-12/README.Bugs --enable-languag" ascii
      $x5 = " %{!c:%e-c required for gnat2scil} gnat1scil %{I*} %{k8:-gnatk8} %{!Q:-quiet}    %{nostdinc*} %{nostdlib*}    %{a} %<dumpdir %<d" ascii
      $x6 = " %{!c:%e-c required for gnat2why} gnat1why %{I*} %{k8:-gnatk8} %{!Q:-quiet}    %{nostdinc*} %{nostdlib*}    %{a} %<dumpdir %<dum" ascii
      $x7 = "The minimum recommended offset between two concurrently-accessed objects to avoid additional performance degradation due to cont" ascii
      $x8 = "  -dumpmachine             Display the compiler's target processor." fullword ascii
      $x9 = "   %{save-temps*:%b.ii} %{!save-temps*:%g.ii}}  %{!save-temps*:%{!no-integrated-cpp:%(cpp_unique_options)}}  %{fmodules-ts:-fmod" ascii
      $x10 = "                     %:exit()}%{fmodules:%{fuselist:gm2lcc %{fshared} %{fpic} %{fPIC} %{B*} %{L*}                         %{ftar" ascii
      $x11 = "%{pg:%{fomit-frame-pointer:%e-pg and -fomit-frame-pointer are incompatible}} %{!iplugindir*:%{fplugin*:%:find-plugindir()}} %1 %" ascii
      $s12 = "-exec --startup           %b_m2%O           %{!fshared:--ar %:objects() %:noobjects() -o %{!save-temps*:%d}%w%g.a }           --" ascii
      $s13 = "The maximum recommended size of contiguous memory occupied by two objects accessed with temporal locality by concurrent threads." ascii
      $s14 = "%{!fsyntax-only:%{!c:%{!M:%{!MM:%{!E:%{!S:    %(linker) %{!fno-use-linker-plugin:%{!fno-lto:     -plugin %(linker_plugin_file)  " ascii
      $s15 = "  (Use '-v --help' to display command line options of sub-processes)." fullword ascii
      $s16 = "Dump the dump tool command line options." fullword ascii
      $s17 = "     %:exit()}}%{c|S:cc1gm2 %{fcpp:-fcppbegin %:exec_prefix(cc1)      -E -lang-asm -traditional-cpp       %(cpp_unique_options) " ascii
      $s18 = "Collect and dump debug information into temporary file if ICE in C/C++ compiler occurred." fullword ascii
      $s19 = "t} -o %{fmakeinit:%b_m2.cpp;:%{!save-temps*:%d}%b_m2.cpp} " fullword ascii
      $s20 = "64-linux-gnu- --enable-shared --enable-linker-build-id --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix -" ascii
      $s21 = " passed on to the various sub-processes invoked by %s.  In order to pass" fullword ascii
      $s22 = "  -###                     Like -v but options quoted and commands not executed." fullword ascii
      $s23 = "save temporary preprocessed files" fullword ascii
      $s24 = "%{-target-help:%:print-asm-header()} %{v} %{w:-W} %{I*} %(asm_debug_option) %{gz|gz=zlib:--compress-debug-sections=zlib} %{gz=no" ascii
      $s25 = "--param=threader-debug=[none|all] Enables verbose dumping of the threader solver." fullword ascii
      $s26 = "    cc1obj -fpreprocessed %b.mi %(cc1_options) %(distro_defaults) %{print-objc-runtime-info} %{gen-decls}                       " ascii
      $s27 = "phobos-checking=release --with-target-system-zlib=auto --enable-objc-gc=auto --enable-multiarch --disable-werror --enable-cet --" ascii
      $s28 = "  Typically the L1 cache line size, but can be smaller to accommodate a variety of target processors with different cache line s" ascii
      $s29 = "                   gm2lgen %{fshared} %{fshared:--terminate --exit}            %{!fno-exceptions:-fcpp} %{fuselist:%b.lst;:%g.ls" ascii
      $s30 = "Process all modules specified on the command line, but only generate code for the module specified by the argument." fullword ascii
      $s31 = "                            gm2lcc %{fshared} %{fpic} %{fPIC} %{B*} %{L*}                         %{ftarget-ar=*} %{ftarget-ranl" ascii
      $s32 = "-directory:-fworking-directory}}} %{O*} %{undef} %{save-temps*:-fpch-preprocess} %(distro_defaults)" fullword ascii
      $s33 = "   %{save-temps*:%b.ii} %{!save-temps*:%g.ii}}  %{!save-temps*:%{!no-integrated-cpp:%(cpp_unique_options)}}  %{fmodules-ts:-fmod" ascii
      $s34 = "MT*} %{MF*} %V -o %{!save-temps*:%d}%g.s %i " fullword ascii
      $s35 = "%{!M:%{!MM:%{!E:cc1 -fpreprocessed %i %(cc1_options) %(distro_defaults) %{!fsyntax-only:%(invoke_as)}}}}" fullword ascii
      $s36 = "passed to the preprocessor if -fcpp is used" fullword ascii
      $s37 = "%{!E:%{!M:%{!MM:  cc1plus -fpreprocessed %i %(cc1_options) %(distro_defaults) %2  %{!fsyntax-only:    %{fmodule-only:%{!S:-o %g." ascii
      $s38 = "%(cpp_unique_options) %1 %{m*} %{std*&ansi&trigraphs} %{W*&pedantic*} %{w} %{f*} %{g*:%{%:debug-level-gt(0):%{g*} %{!fno-working" ascii
      $s39 = "  as %a %Y %b_m2.s -o %{!save-temps*:%d}%b_m2%O  " fullword ascii
      $s40 = "}  cc1plus %{save-temps*|no-integrated-cpp:-fpreprocessed " fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule false_negative_bins_sed {
   strings:
      $s1 = "                 add the contents of script-file to the commands to be executed" fullword ascii
      $s2 = "                 add the script to the commands to be executed" fullword ascii
      $s3 = "  -f script-file, --file=script-file" fullword ascii
      $s4 = "  -e script, --expression=script" fullword ascii
      $s5 = "%s: warning: failed to get security context of %s: %s" fullword ascii
      $s6 = "General help using GNU software: <https://www.gnu.org/gethelp/>." fullword ascii
      $s7 = "lgetfilecon" fullword ascii
      $s8 = "getfscreatecon" fullword ascii
      $s9 = "fgetfilecon" fullword ascii
      $s10 = "%s: warning: failed to set default file creation context to %s: %s" fullword ascii
      $s11 = "couldn't readlink %s: %s" fullword ascii
      $s12 = "                 follow symlinks when processing in place" fullword ascii
      $s13 = "e/r/w commands disabled in sandbox mode" fullword ascii
      $s14 = "* at start of expression" fullword ascii
      $s15 = "  -l N, --line-length=N" fullword ascii
      $s16 = "COMMAND: " fullword ascii
      $s17 = "                 operate in sandbox mode (disable e/r/w commands)." fullword ascii
      $s18 = "missing filename in r/R/w/W commands" fullword ascii
      $s19 = "SELinux is disabled on this system." fullword ascii
      $s20 = "https://www.gnu.org/software/sed/" fullword ascii
      $s21 = "This sed program was built with SELinux support." fullword ascii
      $s22 = "SELinux is enabled on this system." fullword ascii
      $s23 = "GNU sed home page: <https://www.gnu.org/software/sed/>." fullword ascii
      $s24 = "  regex[%d] = %d-%d '" fullword ascii
      $s25 = "couldn't write %llu item to %s: %s" fullword ascii
      $s26 = "couldn't write %llu items to %s: %s" fullword ascii
      $s27 = "                 annotate program execution" fullword ascii
      $s28 = "invalid content of \\{\\}" fullword ascii
      $s29 = "setfscreatecon" fullword ascii
      $s30 = "  --follow-symlinks" fullword ascii
      $s31 = "  -i[SUFFIX], --in-place[=SUFFIX]" fullword ascii
      $s32 = "  -s, --separate" fullword ascii
      $s33 = "+ at start of expression" fullword ascii
      $s34 = "  -E, -r, --regexp-extended" fullword ascii
      $s35 = "  -z, --null-data" fullword ascii
      $s36 = "dfamust" fullword ascii
      $s37 = "  -n, --quiet, --silent" fullword ascii
      $s38 = "  -u, --unbuffered" fullword ascii
      $s39 = "fread_unlocked" fullword ascii
      $s40 = "                 specify the desired line-wrap length for the `l' command" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule false_negative_bins_sort {
   strings:
      $s1 = "couldn't execute compress program (with -d)" fullword ascii
      $s2 = "  -T, --temporary-directory=DIR  use DIR for temporaries, not $TMPDIR or %s;" fullword ascii
      $s3 = "couldn't execute compress program" fullword ascii
      $s4 = "the entire line as the key.  Use --debug to diagnose incorrect key usage." fullword ascii
      $s5 = "getrandom" fullword ascii
      $s6 = "  -C, --check=quiet, --check=silent  like -c, but do not report first bad line" fullword ascii
      $s7 = "                            If F is - then read names from standard input" fullword ascii
      $s8 = "      --compress-program=PROG  compress temporaries with PROG;" fullword ascii
      $s9 = "options '-%s' are incompatible" fullword ascii
      $s10 = "obsolescent key %s used; consider %s instead" fullword ascii
      $s11 = "sched_getaffinity" fullword ascii
      $s12 = "  -h, --human-numeric-sort    compare human readable numbers (e.g., 2K 1G)" fullword ascii
      $s13 = "text ordering performed using simple byte comparison" fullword ascii
      $s14 = "                            for more use temp files" fullword ascii
      $s15 = "  -c, --check, --check=diagnose-first  check for sorted input; do not sort" fullword ascii
      $s16 = "  -t, --field-separator=SEP  use SEP instead of non-blank to blank transition" fullword ascii
      $s17 = "      --random-source=FILE    get random bytes from FILE" fullword ascii
      $s18 = "failed to set locale" fullword ascii
      $s19 = "  -b, --ignore-leading-blanks  ignore leading blanks" fullword ascii
      $s20 = "fread_unlocked" fullword ascii
      $s21 = "field separator %s is treated as a group separator in numbers" fullword ascii
      $s22 = "text ordering performed using %s sorting rules" fullword ascii
      $s23 = "field separator %s is treated as a plus sign in numbers" fullword ascii
      $s24 = "options '-%s' are ignored" fullword ascii
      $s25 = "  -g, --general-numeric-sort  compare according to general numerical value" fullword ascii
      $s26 = "field separator %s is treated as a minus sign in numbers" fullword ascii
      $s27 = "option '-%s' is ignored" fullword ascii
      $s28 = "!\"unexpected mode passed to stream_open\"" fullword ascii
      $s29 = "option '-r' only applies to last-resort comparison" fullword ascii
      $s30 = "field separator %s is treated as a decimal point in numbers" fullword ascii
      $s31 = "8e28329c2296b3a0e66712bfeb89b5ba24e930.debug" fullword ascii
      $s32 = "A_POSIX2_VERSION" fullword ascii
      $s33 = "AUATUSI" fullword ascii
      $s34 = "  or:  %s [OPTION]... --files0-from=F" fullword ascii
      $s35 = "                              decompress them with PROG -d" fullword ascii
      $s36 = "                                numeric -n, random -R, version -V" fullword ascii
      $s37 = "  -V, --version-sort          natural sort of (version) numbers within text" fullword ascii
      $s38 = "      --files0-from=F       read input from the files specified by" fullword ascii
      $s39 = "  -m, --merge               merge already sorted files; do not sort" fullword ascii
      $s40 = "                              without -c, output only the first of an equal run" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule false_negative_bins_tac {
   strings:
      $s1 = "282f4a48024a77bbff57ee209d064f0edf1374.debug" fullword ascii
      $s2 = "AVAUATU1" fullword ascii
      $s3 = "Unmatched [, [^, [:, [., or [=" fullword ascii
      $s4 = "fflush_unlocked" fullword ascii
      $s5 = "failed to create temporary file in %s" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "tacXXXXXX" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "282f4a48024a77bbff57ee209d064f0edf1374" ascii
      $s8 = "failed to rewind stream for %s" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "failed to open %s for writing" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "  -s, --separator=STRING   use STRING as the separator instead of newline" fullword ascii
      $s11 = "%s: write error" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "  -r, --regex              interpret the separator as a regular expression" fullword ascii
      $s13 = "Jay Lepreau" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "  -b, --before             attach the separator before instead of after" fullword ascii
      $s15 = "%s: seek failed" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "separator cannot be empty" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "Write each FILE to standard output, last line first." fullword ascii /* Goodware String - occured 2 times */
      $s18 = "mkostemp" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "\\$XI;]" fullword ascii
      $s20 = "\\$XM9l$`~" fullword ascii
      $s21 = "failed to open %s for reading" fullword ascii /* Goodware String - occured 3 times */
      $s22 = "t$PI9t$Ht" fullword ascii
      $s23 = "H#E tkI" fullword ascii
      $s24 = "tkI9,$~-H" fullword ascii
      $s25 = "t}L;kP" fullword ascii
      $s26 = "D$4PAWH" fullword ascii
      $s27 = "~=I;o0" fullword ascii
      $s28 = "I9mH~.I" fullword ascii
      $s29 = "~D$HfI" fullword ascii
      $s30 = "D$@L;k" fullword ascii
      $s31 = "CXH)khL" fullword ascii
      $s32 = "EXH9E@" fullword ascii
      $s33 = "&H;GX} " fullword ascii
      $s34 = "H9Nh~sL" fullword ascii
      $s35 = "[A\\A]A^" fullword ascii
      $s36 = "E0[]A\\" fullword ascii
      $s37 = "D$XI9D$@||I" fullword ascii
      $s38 = "D$XI9D$@" fullword ascii
      $s39 = "L;kXt*L" fullword ascii
      $s40 = "L;;~\"M;l$0" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule false_negative_bins_xargs {
   strings:
      $s1 = "Execution of xargs will continue now, and it will try to read its input and run commands; if this is not what you wanted to happ" ascii
      $s2 = "failed to redirect standard input of the child process" fullword ascii
      $s3 = "  -t, --verbose                print commands before executing them" fullword ascii
      $s4 = "errno-buffer safe_read failed in xargs_do_exec (this is probably a bug, please report it)" fullword ascii
      $s5 = "File descriptor %d will leak; please report this as a bug, remembering to include a detailed description of the simplest way to " ascii
      $s6 = "                                 before executing the command; useful to run an" fullword ascii
      $s7 = "Usage: %s [OPTION]... COMMAND [INITIAL-ARGS]..." fullword ascii
      $s8 = "  -r, --no-run-if-empty        if there are no arguments, then do not run COMMAND;" fullword ascii
      $s9 = "  -P, --max-procs=MAX-PROCS    run at most MAX-PROCS processes at a time" fullword ascii
      $s10 = "  -p, --interactive            prompt before running commands" fullword ascii
      $s11 = "      --process-slot-var=VAR   set environment variable VAR in child processes" fullword ascii
      $s12 = "  -o, --open-tty               Reopen stdin as /dev/tty in the child process" fullword ascii
      $s13 = "%s: value %s for -%c option should be >= %ld" fullword ascii
      $s14 = "%s: invalid number \"%s\" for -%c option" fullword ascii
      $s15 = "%s: value %s for -%c option should be <= %ld" fullword ascii
      $s16 = "Maximum length of command we could actually use: %lu" fullword ascii
      $s17 = "                                 disables quote and backslash processing and" fullword ascii
      $s18 = "warning: the -E option has no effect if -0 or -d is used." fullword ascii
      $s19 = "  -s, --max-chars=MAX-CHARS    limit length of command line to MAX-CHARS" fullword ascii
      $s20 = "  -n, --max-args=MAX-ARGS      use at most MAX-ARGS arguments per command line" fullword ascii
      $s21 = "      --show-limits            show limits on command-line length" fullword ascii
      $s22 = "https://www.gnu.org/software/findutils/" fullword ascii
      $s23 = "read returned unexpected value %lu; this is probably a bug, please report it" fullword ascii
      $s24 = "program via the %s bug-reporting page at" fullword ascii
      $s25 = "Failed to read from stdin" fullword ascii
      $s26 = "https://savannah.gnu.org/bugs/?group=findutils" fullword ascii
      $s27 = "                                 command line" fullword ascii
      $s28 = "The atexit library function failed" fullword ascii
      $s29 = "WARNING: a NUL character occurred in the input.  It cannot be passed through in the argument list.  Did you mean to use the --nu" ascii
      $s30 = "en, please type the end-of-file keystroke." fullword ascii
      $s31 = "warning: options %s and %s are mutually exclusive, ignoring previous %s value" fullword ascii
      $s32 = "Please see also the documentation at %s." fullword ascii
      $s33 = "                                 (ignored if -0 or -d was specified)" fullword ascii
      $s34 = "Failed to write to stderr" fullword ascii
      $s35 = "you have no web access, by sending email to <%s>." fullword ascii
      $s36 = "                                 if this option is not given, COMMAND will be" fullword ascii
      $s37 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/findutils.debug" fullword ascii
      $s38 = "buildcmd.c" fullword ascii
      $s39 = "                                 logical EOF processing" fullword ascii
      $s40 = "  -i, --replace[=R]            replace R in INITIAL-ARGS with names read" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_find {
   strings:
      $s1 = "DebugExec: launching process (argc=%lu):" fullword ascii
      $s2 = "DebugExec: process (PID=%ld) terminated with exit status: %d" fullword ascii
      $s3 = "      -exec COMMAND ; -exec COMMAND {} + -ok COMMAND ;" fullword ascii
      $s4 = "      -execdir COMMAND ; -execdir COMMAND {} + -okdir COMMAND ;" fullword ascii
      $s5 = "File descriptor %d will leak; please report this as a bug, remembering to include a detailed description of the simplest way to " ascii
      $s6 = "process_all_startpoints" fullword ascii
      $s7 = "fallback_getfilecon(): getfilecon(%s) failed; falling back on lgetfilecon()" fullword ascii
      $s8 = "lgetfilecon" fullword ascii
      $s9 = "fgetfilecon" fullword ascii
      $s10 = "Failed to initialize shared-file hash table" fullword ascii
      $s11 = "failed to compile regular expression '%s': %s" fullword ascii
      $s12 = "Operators (decreasing precedence; -and is implicit where no others are given):" fullword ascii
      $s13 = "slash - dir < 4096" fullword ascii
      $s14 = "file operands cannot be combined with -files0-from" fullword ascii
      $s15 = "XXA NULL argv[0] was passed through an exec system call." fullword ascii
      $s16 = "option -files0-from: standard input must not refer to the same file when combined with -ok, -okdir" fullword ascii
      $s17 = "Failed to restore initial working directory%s%s" fullword ascii
      $s18 = "warning: you have specified a mode pattern %s (which is equivalent to /000). The meaning of -perm /000 has now been changed to b" ascii
      $s19 = "      -readable -writable -executable" fullword ascii
      $s20 = "Failed to save initial working directory%s%s" fullword ascii
      $s21 = "Failed to change directory%s%s" fullword ascii
      $s22 = "Failed to write prompt for -ok" fullword ascii
      $s23 = "https://www.gnu.org/software/findutils/" fullword ascii
      $s24 = "program via the %s bug-reporting page at" fullword ascii
      $s25 = "https://savannah.gnu.org/bugs/?group=findutils" fullword ascii
      $s26 = "Failed to write output (at stage %d)" fullword ascii
      $s27 = "The current directory is included in the PATH environment variable, which is insecure in combination with the %s action of find." ascii
      $s28 = "option -files0-from reading from standard input cannot be combined with -ok, -okdir" fullword ascii
      $s29 = "failed to read file names from file system at or below %s" fullword ascii
      $s30 = "fuse.portal" fullword ascii
      $s31 = "Use '-D help' for a description of the options, or see find(1)" fullword ascii
      $s32 = "%s %c is not supported because Solaris doors are not supported on the platform find was compiled on." fullword ascii
      $s33 = "The relative path %s is included in the PATH environment variable, which is insecure in combination with the %s action of find. " ascii
      $s34 = "warning: you have specified the global option %s after the argument %s, but global options are not positional, i.e., %s affects " ascii
      $s35 = "Unknown argument to %s: %c" fullword ascii
      $s36 = "warning: you have specified the global option %s after the argument %s, but global options are not positional, i.e., %s affects " ascii
      $s37 = "Expression may consist of: operators, options, tests, and actions." fullword ascii
      $s38 = "exec.c" fullword ascii
      $s39 = "rpmatch" fullword ascii
      $s40 = "lsetfilecon" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 700KB and
      8 of them
}

rule false_negative_bins_mv {
   strings:
      $s1 = "  -t, --target-directory=DIRECTORY  move all SOURCE arguments into DIRECTORY" fullword ascii
      $s2 = "failed to stat %s: skipping %s" fullword ascii
      $s3 = "target directory %s" fullword ascii
      $s4 = "lgetfilecon" fullword ascii
      $s5 = "getfscreatecon" fullword ascii
      $s6 = "fgetfilecon" fullword ascii
      $s7 = "  -T, --no-target-directory    treat DEST as a normal file" fullword ascii
      $s8 = "getrandom" fullword ascii
      $s9 = "and --preserve-root=all is in effect" fullword ascii
      $s10 = "getcon" fullword ascii
      $s11 = "error copying %s to %s" fullword ascii
      $s12 = "refusing to remove %s or %s directory: skipping %s" fullword ascii
      $s13 = "security.selinux" fullword ascii
      $s14 = "  or:  %s [OPTION]... -t DIRECTORY SOURCE..." fullword ascii
      $s15 = "%s: unwritable %s (mode %04lo, %s); try anyway? " fullword ascii
      $s16 = "%s: replace %s, overriding mode %04lo (%s)? " fullword ascii
      $s17 = "context_type_get" fullword ascii
      $s18 = "setfscreatecon" fullword ascii
      $s19 = "  -S, --suffix=SUFFIX          override the usual backup suffix" fullword ascii
      $s20 = "The backup suffix is '~', unless set with --suffix or SIMPLE_BACKUP_SUFFIX." fullword ascii
      $s21 = "fsetfilecon" fullword ascii
      $s22 = "rpmatch" fullword ascii
      $s23 = "warning: ignoring --context" fullword ascii
      $s24 = "lsetfilecon" fullword ascii
      $s25 = "warning: source directory %s specified more than once" fullword ascii
      $s26 = " (backup: %s)" fullword ascii
      $s27 = "backing up %s might destroy source;  %s not moved" fullword ascii
      $s28 = "failed to close %s" fullword ascii
      $s29 = "backing up %s might destroy source;  %s not copied" fullword ascii
      $s30 = "overflow reading %s" fullword ascii
      $s31 = "security_compute_create" fullword ascii
      $s32 = "  -b                           like --backup but does not accept an argument" fullword ascii
      $s33 = "selabel_lookup" fullword ascii
      $s34 = "failed to set default file creation context for %s" fullword ascii
      $s35 = "failed to set the security context of %s" fullword ascii
      $s36 = "AWAVAUATUSD" fullword ascii
      $s37 = "acl_get_entry" fullword ascii
      $s38 = "acl_get_tag_type" fullword ascii
      $s39 = "acl_get_file" fullword ascii
      $s40 = "acl_get_fd" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule false_negative_bins_install {
   strings:
      $s1 = "  -t, --target-directory=DIRECTORY  copy all SOURCE arguments into DIRECTORY" fullword ascii
      $s2 = "  -T, --no-target-directory  treat DEST as a normal file" fullword ascii
      $s3 = "                        or all components of --target-directory," fullword ascii
      $s4 = "warning: ignoring --context; it requires an SELinux-enabled kernel" fullword ascii
      $s5 = "warning: %s: context lookup failed" fullword ascii
      $s6 = "  -g, --group=GROUP   set group ownership, instead of process' current group" fullword ascii
      $s7 = "lgetfilecon" fullword ascii
      $s8 = "getfscreatecon" fullword ascii
      $s9 = "fgetfilecon" fullword ascii
      $s10 = "getrandom" fullword ascii
      $s11 = "  -S, --suffix=SUFFIX  override the usual backup suffix" fullword ascii
      $s12 = "warning: %s: failed to change context to %s" fullword ascii
      $s13 = "cannot set target context and preserve it" fullword ascii
      $s14 = "  -C, --compare       compare content of source and destination files, and" fullword ascii
      $s15 = "getcon" fullword ascii
      $s16 = "error copying %s to %s" fullword ascii
      $s17 = "security.selinux" fullword ascii
      $s18 = "  or:  %s [OPTION]... -t DIRECTORY SOURCE..." fullword ascii
      $s19 = "  or:  %s [OPTION]... -d DIRECTORY..." fullword ascii
      $s20 = "%s: unwritable %s (mode %04lo, %s); try anyway? " fullword ascii
      $s21 = "%s: replace %s, overriding mode %04lo (%s)? " fullword ascii
      $s22 = "context_type_get" fullword ascii
      $s23 = "setfscreatecon" fullword ascii
      $s24 = "The backup suffix is '~', unless set with --suffix or SIMPLE_BACKUP_SUFFIX." fullword ascii
      $s25 = "fsetfilecon" fullword ascii
      $s26 = "rpmatch" fullword ascii
      $s27 = "lsetfilecon" fullword ascii
      $s28 = "warning: source directory %s specified more than once" fullword ascii
      $s29 = " (backup: %s)" fullword ascii
      $s30 = "backing up %s might destroy source;  %s not moved" fullword ascii
      $s31 = "failed to close %s" fullword ascii
      $s32 = "backing up %s might destroy source;  %s not copied" fullword ascii
      $s33 = "overflow reading %s" fullword ascii
      $s34 = "security_compute_create" fullword ascii
      $s35 = "selabel_lookup" fullword ascii
      $s36 = "failed to set default file creation context for %s" fullword ascii
      $s37 = "failed to set the security context of %s" fullword ascii
      $s38 = "failed to restore context for %s" fullword ascii
      $s39 = "  -c                  (ignored)" fullword ascii
      $s40 = "warning: security labeling handle failed" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule false_negative_bins_cp {
   strings:
      $s1 = "  -t, --target-directory=DIRECTORY  copy all SOURCE arguments into DIRECTORY" fullword ascii
      $s2 = "warning: ignoring --context; it requires an SELinux-enabled kernel" fullword ascii
      $s3 = "target directory %s" fullword ascii
      $s4 = "lgetfilecon" fullword ascii
      $s5 = "getfscreatecon" fullword ascii
      $s6 = "fgetfilecon" fullword ascii
      $s7 = "  -T, --no-target-directory    treat DEST as a normal file" fullword ascii
      $s8 = "getrandom" fullword ascii
      $s9 = "cannot set target context and preserve it" fullword ascii
      $s10 = "  -H                           follow command-line symbolic links in SOURCE" fullword ascii
      $s11 = "getcon" fullword ascii
      $s12 = "error copying %s to %s" fullword ascii
      $s13 = "security.selinux" fullword ascii
      $s14 = "  or:  %s [OPTION]... -t DIRECTORY SOURCE..." fullword ascii
      $s15 = "                                 attempting to open it (contrast with --force)" fullword ascii
      $s16 = "%s: unwritable %s (mode %04lo, %s); try anyway? " fullword ascii
      $s17 = "%s: replace %s, overriding mode %04lo (%s)? " fullword ascii
      $s18 = "context_type_get" fullword ascii
      $s19 = "setfscreatecon" fullword ascii
      $s20 = "  -S, --suffix=SUFFIX          override the usual backup suffix" fullword ascii
      $s21 = "The backup suffix is '~', unless set with --suffix or SIMPLE_BACKUP_SUFFIX." fullword ascii
      $s22 = "fsetfilecon" fullword ascii
      $s23 = "rpmatch" fullword ascii
      $s24 = "warning: ignoring --context" fullword ascii
      $s25 = "lsetfilecon" fullword ascii
      $s26 = "  -i, --interactive            prompt before overwrite (overrides a previous -n" fullword ascii
      $s27 = "Use --reflink=never to ensure a standard copy is performed." fullword ascii
      $s28 = "      --copy-contents          copy contents of special files when recursive" fullword ascii
      $s29 = "  -n, --no-clobber             do not overwrite an existing file (overrides" fullword ascii
      $s30 = "warning: source directory %s specified more than once" fullword ascii
      $s31 = " (backup: %s)" fullword ascii
      $s32 = "backing up %s might destroy source;  %s not moved" fullword ascii
      $s33 = "failed to close %s" fullword ascii
      $s34 = "backing up %s might destroy source;  %s not copied" fullword ascii
      $s35 = "overflow reading %s" fullword ascii
      $s36 = "security_compute_create" fullword ascii
      $s37 = "  -b                           like --backup but does not accept an argument" fullword ascii
      $s38 = "selabel_lookup" fullword ascii
      $s39 = "failed to set default file creation context for %s" fullword ascii
      $s40 = "failed to set the security context of %s" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule false_negative_bins_openssl {
   strings:
      $x1 = "%s:%s:%d:CMP %s: no cmp command to execute%s%s%s" fullword ascii
      $x2 = "%s:%s:%d:CMP %s: server credentials (-srv_secret or -srv_cert) must be given if -use_mock_srv or -port is used%s%s%s" fullword ascii
      $s3 = "%s:%s:%d:CMP %s: no -newkey option given with private key for POPO, -csr option only provides public key%s%s%s" fullword ascii
      $s4 = "%s:%s:%d:CMP %s: -failurebits overrides -failure%s%s%s" fullword ascii
      $s5 = "%s:%s:%d:CMP %s: -oldcert option is ignored for command 'genm'%s%s%s" fullword ascii
      $s6 = "%s:%s:%d:CMP %s: -csr option is ignored for command 'genm'%s%s%s" fullword ascii
      $s7 = "%s:%s:%d:CMP %s: missing -newkey (or -key) to be certified and no -csr, -oldcert, or -cert given for fallback public key%s%s%s" fullword ascii
      $s8 = "%s:%s:%d:CMP %s: -cert and -key not used for protection since -secret is given%s%s%s" fullword ascii
      $s9 = "%s:%s:%d:CMP %s: must give -key or -secret unless -unprotected_requests is used%s%s%s" fullword ascii
      $s10 = "Use specified hex-encoded key to decrypt/encrypt recipients or content" fullword ascii
      $s11 = "Error getting private key password" fullword ascii
      $s12 = "%s:%s:%d:CMP %s: unknown cmp command '%s'%s%s" fullword ascii
      $s13 = "Key to decrypt the private key or cert files if encrypted. Better use -passin" fullword ascii
      $s14 = "%s:%s:%d:CMP %s: The -port option excludes -server and -use_mock_srv%s%s%s" fullword ascii
      $s15 = "%s:%s:%d:CMP %s: -tls_used option not supported with -port option%s%s%s" fullword ascii
      $s16 = "%s:%s:%d:CMP %s: ignoring -proxy option since -server is not given%s%s%s" fullword ascii
      $s17 = "%s:%s:%d:CMP %s: cannot set up error reporting and logging for %s%s%s" fullword ascii
      $s18 = "%s:%s:%d:CMP %s: -newkey %s%s%s" fullword ascii
      $s19 = "%s:%s:%d:CMP %s: The -port option does not support -rspin and -rspout%s%s%s" fullword ascii
      $s20 = "%s:%s:%d:CMP %s: must give both -srv_cert and -srv_key options or neither%s%s%s" fullword ascii
      $s21 = "%s:%s:%d:CMP %s: server will not be able to handle PBM-protected requests since -srv_secret is not given%s%s%s" fullword ascii
      $s22 = "%s:%s:%d:CMP %s: missing -tls_key option%s%s%s" fullword ascii
      $s23 = "%s: -proxy requires use of -connect or target parameter" fullword ascii
      $s24 = "%s:%s:%d:CMP %s: The -port option does not support -reqin and -reqout%s%s%s" fullword ascii
      $s25 = "%s:%s:%d:CMP %s: -failurebits out of range%s%s%s" fullword ascii
      $s26 = "%s:%s:%d:CMP %s: missing -newkey (or -key) option for POPO%s%s%s" fullword ascii
      $s27 = "%s:%s:%d:CMP %s: -newkeytype %s%s%s" fullword ascii
      $s28 = "%s:%s:%d:CMP %s: must give both -cert and -key options or neither%s%s%s" fullword ascii
      $s29 = "%s:%s:%d:CMP %s: -failure out of range, should be >= 0 and <= %d%s%s" fullword ascii
      $s30 = "%s:%s:%d:CMP %s: ignoring -no_proxy option since -server is not given%s%s%s" fullword ascii
      $s31 = "EVP_KEYEXCH_get0_description" fullword ascii
      $s32 = "%s:%s:%d:CMP %s: unable to use TLS client private key '%s'%s%s" fullword ascii
      $s33 = "%s:%s:%d:CMP %s: will not authenticate server due to missing -secret, -trusted, or -srvcert%s%s%s" fullword ascii
      $s34 = "child process: %ld, term signal %d%s" fullword ascii
      $s35 = "Restrict encoded output to public components" fullword ascii
      $s36 = "%s:%s:%d:CMP %s: CSR self-signature does not match the contents%s%s%s" fullword ascii
      $s37 = "%s:%s:%d:CMP %s: could not get ITAV details%s%s%s" fullword ascii
      $s38 = "%s:%s:%d:CMP %s: given -subject '%s' overrides the subject of '%s' for KUR%s" fullword ascii
      $s39 = "mail.example.com" fullword ascii
      $s40 = "Failed to process value (%s)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule false_negative_bins_nohup {
   strings:
      $s1 = "To save output to FILE, use '%s COMMAND > FILE'." fullword ascii
      $s2 = "If standard input is a terminal, redirect it from an unreadable file." fullword ascii
      $s3 = "8418c2c3acee189b74593d19fd9839f97fb397.debug" fullword ascii
      $s4 = "'$HOME/nohup.out' otherwise." fullword ascii
      $s5 = "If standard output is a terminal, append output to 'nohup.out' if possible," fullword ascii
      $s6 = "If standard error is a terminal, redirect it to standard output." fullword ascii /* Goodware String - occured 1 times */
      $s7 = "ignoring input and appending output to %s" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "ignoring input" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "  or:  %s OPTION" fullword ascii
      $s10 = "failed to render standard input unusable" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "ignoring input and redirecting stderr to stdout" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "redirecting stderr to stdout" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "8418c2c3acee189b74593d19fd9839f97fb397" ascii
      $s14 = "Run COMMAND, ignoring hangup signals." fullword ascii /* Goodware String - occured 2 times */
      $s15 = "Usage: %s COMMAND [ARG]..." fullword ascii /* Goodware String - occured 2 times */
      $s16 = "appending output to %s" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "nohup.out" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "failed to redirect standard error" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "failed to run command %s" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_dd {
   strings:
      $s1 = "Sending a %s signal to a running 'dd' process makes it" fullword ascii
      $s2 = "%ld bytes copied, %s, %s" fullword ascii
      $s3 = "%ld bytes (%s) copied, %s, %s" fullword ascii
      $s4 = "%ld bytes (%s, %s) copied, %s, %s" fullword ascii
      $s5 = "%ld byte copied, %s, %s" fullword ascii
      $s6 = "  directory  fail unless a directory" fullword ascii
      $s7 = "  excl      fail if the output file already exists" fullword ascii
      $s8 = "you probably want conv=notrunc with oflag=append" fullword ascii
      $s9 = "memory exhausted by output buffer of size %td bytes (%s)" fullword ascii
      $s10 = "warning: %s is a zero multiplier; use %s if that is intended" fullword ascii
      $s11 = "warning: partial read (%td bytes); suggest iflag=fullblock" fullword ascii
      $s12 = "memory exhausted by input buffer of size %td bytes (%s)" fullword ascii
      $s13 = "  noerror   continue after read errors" fullword ascii
      $s14 = "warning: partial read (%td byte); suggest iflag=fullblock" fullword ascii
      $s15 = "                  overrides ibs and obs" fullword ascii
      $s16 = "failed to truncate to %ld bytes in output file %s" fullword ascii
      $s17 = "invalid status level" fullword ascii
      $s18 = "  nofollow  do not follow symlinks" fullword ascii
      $s19 = "  iflag=FLAGS     read as per the comma separated symbol list" fullword ascii
      $s20 = "status" fullword ascii /* Goodware String - occured 657 times */
      $s21 = "  or:  %s OPTION" fullword ascii
      $s22 = "GLIBC_2.16" fullword ascii
      $s23 = "aligned_alloc" fullword ascii
      $s24 = "seek_bytes" fullword ascii
      $s25 = "failed to turn off O_DIRECT: %s" fullword ascii /* Goodware String - occured 1 times */
      $s26 = "invalid output flag" fullword ascii /* Goodware String - occured 1 times */
      $s27 = "invalid conversion" fullword ascii /* Goodware String - occured 1 times */
      $s28 = "warning: invalid file offset after failed read" fullword ascii /* Goodware String - occured 1 times */
      $s29 = "  nonblock  use non-blocking I/O" fullword ascii
      $s30 = "  fullblock  accumulate full blocks of input (iflag only)" fullword ascii
      $s31 = "count_bytes" fullword ascii
      $s32 = "9f954969893171a6b23be9244b941749e1257f.debug" fullword ascii
      $s33 = "cannot combine direct and nocache" fullword ascii /* Goodware String - occured 1 times */
      $s34 = "If N ends in 'B', it counts bytes not blocks." fullword ascii
      $s35 = "failed to discard cache for: %s" fullword ascii /* Goodware String - occured 1 times */
      $s36 = "%.0f s" fullword ascii /* Goodware String - occured 1 times */
      $s37 = "%ld+%ld records out" fullword ascii
      $s38 = "skip_bytes" fullword ascii
      $s39 = "%s: cannot skip" fullword ascii /* Goodware String - occured 1 times */
      $s40 = "nolinks" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule false_negative_bins_chroot {
   strings:
      $s1 = "If no command is given, run '\"$SHELL\" -i' (default: '/bin/sh -i')." fullword ascii
      $s2 = "failed to get supplemental groups" fullword ascii
      $s3 = "option --skip-chdir only permitted if NEWROOT is old %s" fullword ascii
      $s4 = "      --userspec=USER:GROUP  specify user and group (ID or name) to use" fullword ascii
      $s5 = "failed to set supplemental groups" fullword ascii
      $s6 = "  or:  %s OPTION" fullword ascii
      $s7 = "warning: '.' should be ':'" fullword ascii
      $s8 = "failed to set user-ID" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "invalid group list %s" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "failed to set group-ID" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "no group specified for unknown uid: %d" fullword ascii
      $s12 = "20f41fb77ba1e8a96830f513e921ee56c01ed7.debug" fullword ascii
      $s13 = "Usage: %s [OPTION] NEWROOT [COMMAND [ARG]...]" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "skip-chdir" fullword ascii
      $s15 = "      --skip-chdir           do not change working directory to %s" fullword ascii
      $s16 = "cannot chdir to root directory" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "invalid spec" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "Roland McGrath" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "Run COMMAND with root directory set to NEWROOT." fullword ascii /* Goodware String - occured 2 times */
      $s20 = "cannot change root directory to %s" fullword ascii /* Goodware String - occured 2 times */
      $s21 = "failed to run command %s" fullword ascii /* Goodware String - occured 3 times */
      $s22 = "userspec" fullword ascii /* Goodware String - occured 3 times */
      $s23 = "D$@L9l$8" fullword ascii
      $s24 = "invalid user" fullword ascii /* Goodware String - occured 4 times */
      $s25 = "getgrouplist" fullword ascii /* Goodware String - occured 4 times */
      $s26 = "invalid group %s" fullword ascii /* Goodware String - occured 4 times */
      $s27 = "20f41fb77ba1e8a96830f513e921ee56c01ed7" ascii
      $s28 = "invalid group" fullword ascii /* Goodware String - occured 4 times */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_nice {
   strings:
      $s1 = "%d (most favorable to the process) to %d (least favorable to the process)." fullword ascii
      $s2 = "With no COMMAND, print the current niceness.  Niceness values range from" fullword ascii
      $s3 = "f7f02f94c37284202646714455d390fc5c8ddf.debug" fullword ascii
      $s4 = "  -n, --adjustment=N   add integer N to the niceness (default 10)" fullword ascii
      $s5 = "a command must be given with an adjustment" fullword ascii /* Goodware String - occured 2 times */
      $s6 = "cannot get niceness" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "Usage: %s [OPTION] [COMMAND [ARG]...]" fullword ascii /* Goodware String - occured 2 times */
      $s8 = "Run COMMAND with an adjusted niceness, which affects process scheduling." fullword ascii /* Goodware String - occured 2 times */
      $s9 = "cannot set niceness" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "invalid adjustment %s" fullword ascii /* Goodware String - occured 2 times */
      $s11 = "f7f02f94c37284202646714455d390fc5c8ddf" ascii
      $s12 = " &FqDU" fullword ascii
      $s13 = "xstrtol" fullword ascii /* Goodware String - occured 4 times */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_stdbuf {
   strings:
      $s1 = "Run COMMAND, with modified buffering operations for its standard streams." fullword ascii
      $s2 = "Usage: %s OPTION... COMMAND" fullword ascii
      $s3 = "/usr/libexec/coreutils" fullword ascii
      $s4 = "NOTE: If COMMAND adjusts the buffering of its standard streams ('tee' does" fullword ascii
      $s5 = "line buffering stdin is meaningless" fullword ascii
      $s6 = "for example) then that will override corresponding changes by 'stdbuf'." fullword ascii
      $s7 = "  -o, --output=MODE  adjust standard output stream buffering" fullword ascii
      $s8 = "failed to find %s" fullword ascii
      $s9 = "failed to update the environment with %s" fullword ascii
      $s10 = "%s=%s:%s" fullword ascii
      $s11 = "  -e, --error=MODE   adjust standard error stream buffering" fullword ascii
      $s12 = "you must specify a buffering mode option" fullword ascii
      $s13 = "%s%c=%lu" fullword ascii
      $s14 = "%s%c=L" fullword ascii
      $s15 = "stdbuf" fullword ascii
      $s16 = "EGkKMPTYZ0" fullword ascii
      $s17 = "This option is invalid with standard input." fullword ascii
      $s18 = "and are thus unaffected by 'stdbuf' settings." fullword ascii
      $s19 = "If MODE is '0' the corresponding stream will be unbuffered." fullword ascii
      $s20 = "size set to MODE bytes." fullword ascii
      $s21 = "Otherwise MODE is a number which may be followed by one of the following:" fullword ascii
      $s22 = "If MODE is 'L' the corresponding stream will be line buffered." fullword ascii
      $s23 = "_STDBUF_" fullword ascii
      $s24 = "libstdbuf.so" fullword ascii
      $s25 = "src/stdbuf.c" fullword ascii
      $s26 = "/usr/lib/x86_64-linux-gnu/coreutils" fullword ascii
      $s27 = "Binary prefixes can be used, too: KiB=K, MiB=M, and so on." fullword ascii
      $s28 = "  -i, --input=MODE   adjust standard input stream buffering" fullword ascii
      $s29 = "0 <= opt_fileno && opt_fileno < ARRAY_CARDINALITY (stdbuf)" fullword ascii
      $s30 = "failed to run command %s" fullword ascii /* Goodware String - occured 3 times */
      $s31 = "Padraig Brady" fullword ascii /* Goodware String - occured 3 times */
      $s32 = "+i:o:e:" fullword ascii
      $s33 = "KB 1000, K 1024, MB 1000*1000, M 1024*1024, and so on for G, T, P, E, Z, Y." fullword ascii
      $s34 = "In this case the corresponding stream will be fully buffered with the buffer" fullword ascii
      $s35 = "Also some filters (like 'dd' and 'cat' etc.) don't use streams for I/O," fullword ascii
      $s36 = "6cc9c2e1b9032eee49f07cae565e126f1a73e8.debug" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_timeout {
   strings:
      $s1 = "the monitored command dumped core" fullword ascii
      $s2 = "warning: disabling core dumps failed" fullword ascii
      $s3 = "  124  if COMMAND times out, and --preserve-status is not specified" fullword ascii
      $s4 = "  125  if the timeout command itself fails" fullword ascii
      $s5 = "sending signal %s to command %s" fullword ascii
      $s6 = "  -    the exit status of COMMAND otherwise" fullword ascii
      $s7 = "unknown status from command (%d)" fullword ascii
      $s8 = "Upon timeout, send the TERM signal to COMMAND, if no other SIGNAL specified." fullword ascii
      $s9 = "  126  if COMMAND is found but cannot be invoked" fullword ascii
      $s10 = "  137  if COMMAND (or timeout itself) is sent the KILL (9) signal (128+9)" fullword ascii
      $s11 = "AA NULL argv[0] was passed through an exec system call." fullword ascii
      $s12 = "The TERM signal kills any process that does not block or catch that signal." fullword ascii
      $s13 = "                 also send a KILL signal if COMMAND is still running" fullword ascii
      $s14 = "                   allow COMMAND to read from the TTY and get TTY signals;" fullword ascii
      $s15 = "                   command times out" fullword ascii
      $s16 = "  -s, --signal=SIGNAL" fullword ascii
      $s17 = "  127  if COMMAND cannot be found" fullword ascii
      $s18 = "  -k, --kill-after=DURATION" fullword ascii
      $s19 = "  -v, --verbose  diagnose to stderr any signal sent upon timeout" fullword ascii
      $s20 = "newlocale" fullword ascii
      $s21 = "                 exit with the same status as COMMAND, even when the" fullword ascii
      $s22 = "  or:  %s [OPTION]" fullword ascii
      $s23 = "                 when not running timeout directly from a shell prompt," fullword ascii
      $s24 = "edf383f73809da039e8802cc3422daac38959e.debug" fullword ascii
      $s25 = "                   in this mode, children of COMMAND will not be timed out" fullword ascii
      $s26 = "strtod_l" fullword ascii
      $s27 = "__libc_current_sigrtmax" fullword ascii
      $s28 = "__libc_current_sigrtmin" fullword ascii
      $s29 = "error waiting for command" fullword ascii /* Goodware String - occured 1 times */
      $s30 = "EXIT status:" fullword ascii
      $s31 = "A duration of 0 disables the associated timeout." fullword ascii
      $s32 = "warning: timer_create" fullword ascii /* Goodware String - occured 1 times */
      $s33 = "DURATION is a floating point number with an optional suffix:" fullword ascii /* Goodware String - occured 1 times */
      $s34 = "'s' for seconds (the default), 'm' for minutes, 'h' for hours or 'd' for days." fullword ascii
      $s35 = "Start COMMAND, and kill it if still running after DURATION." fullword ascii /* Goodware String - occured 1 times */
      $s36 = "edf383f73809da039e8802cc3422daac38959e" ascii
      $s37 = "warning: sigprocmask" fullword ascii
      $s38 = "warning: timer_settime" fullword ascii /* Goodware String - occured 1 times */
      $s39 = "kill-after" fullword ascii /* Goodware String - occured 1 times */
      $s40 = "preserve-status" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_base64 {
   strings:
      $s1 = "The data are encoded as described for the %s alphabet in RFC 4648." fullword ascii
      $s2 = "the formal %s alphabet.  Use --ignore-garbage to attempt to recover" fullword ascii
      $s3 = "  -w, --wrap=COLS       wrap encoded lines after COLS character (default 76)." fullword ascii
      $s4 = "  -i, --ignore-garbage  when decoding, ignore non-alphabet characters" fullword ascii
      $s5 = "4f8e84ab43dfde53eba9ece42de3333215f385.debug" fullword ascii
      $s6 = "fread_unlocked" fullword ascii
      $s7 = "invalid wrap size" fullword ascii
      $s8 = "Base%d encode or decode FILE, or standard input, to standard output." fullword ascii
      $s9 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/A NULL argv[0] was passed through an exec system call." fullword ascii
      $s10 = "VUUUUUUUAV1" fullword ascii
      $s11 = "  -d, --decode          decode data" fullword ascii
      $s12 = "from any other non-alphabet bytes in the encoded stream." fullword ascii /* Goodware String - occured 1 times */
      $s13 = "ignore-garbage" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "4f8e84ab43dfde53eba9ece42de3333215f385" ascii
      $s15 = "Simon Josefsson" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "When decoding, the input may contain newlines in addition to the bytes of" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "xstrtoimax" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "closing standard input" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "D$(I;D$0sdH" fullword ascii
      $s20 = "E(I;E0s]H" fullword ascii
      $s21 = "Usage: %s [OPTION]... [FILE]" fullword ascii /* Goodware String - occured 5 times */
      $s22 = "invalid input" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_basenc {
   strings:
      $s1 = "  -w, --wrap=COLS       wrap encoded lines after COLS character (default 76)." fullword ascii
      $s2 = "the formal alphabet.  Use --ignore-garbage to attempt to recover" fullword ascii
      $s3 = "  -i, --ignore-garbage  when decoding, ignore non-alphabet characters" fullword ascii
      $s4 = "fread_unlocked" fullword ascii
      $s5 = "      --base64url       file- and url-safe base64 (RFC4648 section 5)" fullword ascii
      $s6 = "invalid wrap size" fullword ascii
      $s7 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/A NULL argv[0] was passed through an exec system call." fullword ascii
      $s8 = "missing encoding type" fullword ascii
      $s9 = "basenc encode or decode FILE, or standard input, to standard output." fullword ascii
      $s10 = "VUUUUUUUAV1" fullword ascii
      $s11 = "  -d, --decode          decode data" fullword ascii
      $s12 = "basenc" fullword ascii
      $s13 = "gfffffffAV1" fullword ascii
      $s14 = "from any other non-alphabet bytes in the encoded stream." fullword ascii /* Goodware String - occured 1 times */
      $s15 = "ignore-garbage" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "Simon Josefsson" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "When decoding, the input may contain newlines in addition to the bytes of" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "A(H;A0" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "Assaf Gordon" fullword ascii
      $s20 = "QRSTUV89:;<=>?@0123456789ABCDEFGHIJKLMNOP" fullword ascii
      $s21 = "base32hex_encode" fullword ascii
      $s22 = "src/basenc.c" fullword ascii
      $s23 = "3c440362e399c3446d1b9a1fb307ff1b9d9fd4.debug" fullword ascii
      $s24 = "ABCDEFGHIJ:;<=>?@KLMNOPQRSTUVWXYZ234567" fullword ascii
      $s25 = "invalid input (length must be multiple of 4 characters)" fullword ascii
      $s26 = "base2msbf" fullword ascii
      $s27 = "base2lsbf" fullword ascii
      $s28 = "0x32 <= *p && *p <= 0x5a" fullword ascii
      $s29 = "base32hex" fullword ascii
      $s30 = "base64url" fullword ascii
      $s31 = "      --base16          hex encoding (RFC4648 section 8)" fullword ascii
      $s32 = "      --base32hex       extended hex alphabet base32 (RFC4648 section 7)" fullword ascii
      $s33 = "      --base32          same as 'base32' program (RFC4648 section 6)" fullword ascii
      $s34 = "      --base64          same as 'base64' program (RFC4648 section 4)" fullword ascii
      $s35 = "      --z85             ascii85-like encoding (ZeroMQ spec:32/Z85);" fullword ascii
      $s36 = "xstrtoimax" fullword ascii /* Goodware String - occured 3 times */
      $s37 = "closing standard input" fullword ascii /* Goodware String - occured 3 times */
      $s38 = "base16" fullword ascii
      $s39 = "base32" fullword ascii
      $s40 = "$[]A\\A]A^" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_base32 {
   strings:
      $s1 = "The data are encoded as described for the %s alphabet in RFC 4648." fullword ascii
      $s2 = "the formal %s alphabet.  Use --ignore-garbage to attempt to recover" fullword ascii
      $s3 = "  -w, --wrap=COLS       wrap encoded lines after COLS character (default 76)." fullword ascii
      $s4 = "  -i, --ignore-garbage  when decoding, ignore non-alphabet characters" fullword ascii
      $s5 = "fread_unlocked" fullword ascii
      $s6 = "invalid wrap size" fullword ascii
      $s7 = "Base%d encode or decode FILE, or standard input, to standard output." fullword ascii
      $s8 = "  -d, --decode          decode data" fullword ascii
      $s9 = "gfffffffAV1" fullword ascii
      $s10 = "from any other non-alphabet bytes in the encoded stream." fullword ascii /* Goodware String - occured 1 times */
      $s11 = "ignore-garbage" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "Simon Josefsson" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "When decoding, the input may contain newlines in addition to the bytes of" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "bb3572f54c129e3ea67a61330bfc8d1c96f7c0.debug" fullword ascii
      $s15 = "xstrtoimax" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "closing standard input" fullword ascii /* Goodware String - occured 3 times */
      $s17 = "base32" fullword ascii
      $s18 = "D$(I;D$0sdH" fullword ascii
      $s19 = "E(I;E0sbH" fullword ascii
      $s20 = "bb3572f54c129e3ea67a61330bfc8d1c96f7c0" ascii
      $s21 = "Usage: %s [OPTION]... [FILE]" fullword ascii /* Goodware String - occured 5 times */
      $s22 = "invalid input" fullword ascii /* Goodware String - occured 5 times */
      $s23 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_shuf {
   strings:
      $s1 = "getrandom" fullword ascii
      $s2 = "  or:  %s -i LO-HI [OPTION]..." fullword ascii
      $s3 = "  or:  %s -e [OPTION]... [ARG]..." fullword ascii
      $s4 = "      --random-source=FILE  get random bytes from FILE" fullword ascii
      $s5 = "  -n, --head-count=COUNT    output at most COUNT lines" fullword ascii
      $s6 = "fread_unlocked" fullword ascii
      $s7 = "too many input lines" fullword ascii
      $s8 = "invalid input range" fullword ascii
      $s9 = "no lines to repeat" fullword ascii
      $s10 = "head-count" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "invalid line count: %s" fullword ascii
      $s12 = "72453d829a350c8376c0512a99cec378c04a64.debug" fullword ascii
      $s13 = "cannot combine -e and -i options" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "input-range" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "multiple -i options specified" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "Write a random permutation of the input lines to standard output." fullword ascii /* Goodware String - occured 1 times */
      $s17 = "  -z, --zero-terminated     line delimiter is NUL, not newline" fullword ascii
      $s18 = "  -o, --output=FILE         write result to FILE instead of standard output" fullword ascii
      $s19 = "%s: end of file" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "  -i, --input-range=LO-HI   treat each number LO through HI as an input line" fullword ascii
      $s21 = "  -e, --echo                treat each ARG as an input line" fullword ascii
      $s22 = "multiple output files specified" fullword ascii /* Goodware String - occured 3 times */
      $s23 = "multiple random sources specified" fullword ascii /* Goodware String - occured 3 times */
      $s24 = "random-source" fullword ascii /* Goodware String - occured 3 times */
      $s25 = "D$+A8G" fullword ascii
      $s26 = "72453d829a350c8376c0512a99cec378c04a64" ascii
      $s27 = "L$/:L(" fullword ascii
      $s28 = "ei:n:o:rz" fullword ascii
      $s29 = "Usage: %s [OPTION]... [FILE]" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_csplit {
   strings:
      $s1 = "Read standard input if FILE is -" fullword ascii
      $s2 = "  -b, --suffix-format=FORMAT  use sprintf FORMAT instead of %02d" fullword ascii
      $s3 = "%s: closing delimiter '%c' missing" fullword ascii
      $s4 = "%s: '}' is required in repeat count" fullword ascii
      $s5 = "  -k, --keep-files           do not remove output files on errors" fullword ascii
      $s6 = "AVAUATU1" fullword ascii
      $s7 = "Each PATTERN may be:" fullword ascii
      $s8 = "%s}: integer required between '{' and '}'" fullword ascii
      $s9 = "suppress-matched" fullword ascii
      $s10 = "src/csplit.c" fullword ascii
      $s11 = " on repetition %s" fullword ascii
      $s12 = "A line OFFSET is an integer optionally preceded by '+' or '-'" fullword ascii
      $s13 = "Unmatched [, [^, [:, [., or [=" fullword ascii
      $s14 = "invalid flags in conversion specification: %%%c%c" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "  -z, --elide-empty-files    remove empty output files" fullword ascii
      $s16 = "  -n, --digits=DIGITS        use specified number of digits instead of 2" fullword ascii
      $s17 = "missing conversion specifier in suffix" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "suffix-format" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "invalid conversion specifier in suffix: %c" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "invalid conversion specifier in suffix: \\%.3o" fullword ascii /* Goodware String - occured 2 times */
      $s21 = "      --suppress-matched     suppress the lines matching PATTERN" fullword ascii
      $s22 = "missing %% conversion specification in suffix" fullword ascii /* Goodware String - occured 2 times */
      $s23 = "%s: integer expected after delimiter" fullword ascii /* Goodware String - occured 2 times */
      $s24 = "write error for %s" fullword ascii /* Goodware String - occured 2 times */
      $s25 = "Usage: %s [OPTION]... FILE PATTERN..." fullword ascii /* Goodware String - occured 2 times */
      $s26 = "and output byte counts of each piece to standard output." fullword ascii /* Goodware String - occured 2 times */
      $s27 = "%s: line number out of range" fullword ascii /* Goodware String - occured 2 times */
      $s28 = "line number %s is smaller than preceding line number, %s" fullword ascii /* Goodware String - occured 2 times */
      $s29 = "  %REGEXP%[OFFSET]   skip to, but not including a matching line" fullword ascii
      $s30 = "f:b:kn:sqz" fullword ascii /* Goodware String - occured 2 times */
      $s31 = "%s: invalid regular expression: %s" fullword ascii /* Goodware String - occured 2 times */
      $s32 = "  -s, --quiet, --silent      do not print counts of output file sizes" fullword ascii
      $s33 = "warning: line number %s is the same as preceding line number" fullword ascii /* Goodware String - occured 2 times */
      $s34 = "input disappeared" fullword ascii /* Goodware String - occured 2 times */
      $s35 = "too many %% conversion specifications in suffix" fullword ascii /* Goodware String - occured 2 times */
      $s36 = "  -f, --prefix=PREFIX        use PREFIX instead of 'xx'" fullword ascii
      $s37 = "%s: line number must be greater than zero" fullword ascii /* Goodware String - occured 2 times */
      $s38 = "%s: invalid pattern" fullword ascii /* Goodware String - occured 2 times */
      $s39 = "%s: %s: line number out of range" fullword ascii /* Goodware String - occured 2 times */
      $s40 = "  /REGEXP/[OFFSET]   copy up to but not including a matching line" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule false_negative_bins_pr {
   strings:
      $s1 = "  -h, --header=HEADER" fullword ascii
      $s2 = "  -t, --omit-header  omit page headers and trailers;" fullword ascii
      $s3 = "                    (by a 3-line page header with -F or a 5-line header" fullword ascii
      $s4 = "  -D, --date-format=FORMAT" fullword ascii
      $s5 = "  -S[STRING], --sep-string[=STRING]" fullword ascii
      $s6 = "  -r, --no-file-warnings" fullword ascii
      $s7 = "  -o, --indent=MARGIN" fullword ascii
      $s8 = "  -COLUMN, --columns=COLUMN" fullword ascii
      $s9 = "  -d, --double-space" fullword ascii
      $s10 = "  -N, --first-line-number=NUMBER" fullword ascii
      $s11 = "  +FIRST_PAGE[:LAST_PAGE], --pages=FIRST_PAGE[:LAST_PAGE]" fullword ascii
      $s12 = "  -s[CHAR], --separator[=CHAR]" fullword ascii
      $s13 = "  -T, --omit-pagination" fullword ascii
      $s14 = "  -e[CHAR[WIDTH]], --expand-tabs[=CHAR[WIDTH]]" fullword ascii
      $s15 = "  -n[SEP[DIGITS]], --number-lines[=SEP[DIGITS]]" fullword ascii
      $s16 = "  -w, --width=PAGE_WIDTH" fullword ascii
      $s17 = "  -v, --show-nonprinting" fullword ascii
      $s18 = "  -c, --show-control-chars" fullword ascii
      $s19 = "  -W, --page-width=PAGE_WIDTH" fullword ascii
      $s20 = "  -a, --across      print columns across rather than down, used together" fullword ascii
      $s21 = "  -l, --length=PAGE_LENGTH" fullword ascii
      $s22 = "  -F, -f, --form-feed" fullword ascii
      $s23 = "  -i[CHAR[WIDTH]], --output-tabs[=CHAR[WIDTH]]" fullword ascii
      $s24 = "f4d3a45c2f65140284b9d3d2c25ea3faacecb8.debug" fullword ascii
      $s25 = "  -J, --join-lines  merge full lines, turns off -W line truncation, no column" fullword ascii
      $s26 = "                    -h \"\" prints a blank line, don't use -h\"\"" fullword ascii
      $s27 = "                    options (-COLUMN|-a -COLUMN|-m) except -w is set" fullword ascii
      $s28 = "                    affect -w or -W, MARGIN will be added to PAGE_WIDTH" fullword ascii
      $s29 = "                    unless -a is used. Balance number of lines in the" fullword ascii
      $s30 = "                    is the <TAB> character without -w and 'no char' with -w." fullword ascii
      $s31 = "                    implies -t if PAGE_LENGTH <= 10" fullword ascii
      $s32 = "invalid number of columns" fullword ascii
      $s33 = "'-%c' extra characters or invalid number in the argument: %s" fullword ascii
      $s34 = "Page %lu" fullword ascii
      $s35 = "cannot specify number of columns when printing in parallel" fullword ascii /* Goodware String - occured 1 times */
      $s36 = "'--pages=FIRST_PAGE[:LAST_PAGE]' missing argument" fullword ascii
      $s37 = "                    omit page headers and trailers, eliminate any pagination" fullword ascii
      $s38 = "'-W PAGE_WIDTH' invalid number of characters" fullword ascii
      $s39 = "%*s%s%*s%s%*s%s" fullword ascii /* Goodware String - occured 1 times */
      $s40 = "page number overflow" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_grep {
   strings:
      $s1 = "if any error occurs and -q is not given, the exit status is 2." fullword ascii
      $s2 = "<https://git.sv.gnu.org/cgit/grep.git/tree/AUTHORS>." fullword ascii
      $s3 = "* at start of expression" fullword ascii
      $s4 = "pcre2_get_error_message_8" fullword ascii
      $s5 = "https://www.gnu.org/software/grep/" fullword ascii
      $s6 = "%s: binary file matches" fullword ascii
      $s7 = "%s: internal PCRE error: %d" fullword ascii
      $s8 = "invalid content of \\{\\}" fullword ascii
      $s9 = "pcre2_get_ovector_pointer_8" fullword ascii
      $s10 = "program error" fullword ascii
      $s11 = "+ at start of expression" fullword ascii
      $s12 = "dfamust" fullword ascii
      $s13 = "sigaltstack" fullword ascii
      $s14 = "  -d, --directories=ACTION  how to handle directories;" fullword ascii
      $s15 = "  -L, --files-without-match  print only names of FILEs with no selected lines" fullword ascii
      $s16 = "  -B, --before-context=NUM  print NUM lines of leading context" fullword ascii
      $s17 = "warning: --unix-byte-offsets (-u) is obsolete" fullword ascii
      $s18 = "  -R, --dereference-recursive  likewise, but follow all symlinks" fullword ascii
      $s19 = "posixawk" fullword ascii
      $s20 = "  -l, --files-with-matches  print only names of FILEs with selected lines" fullword ascii
      $s21 = "recursive, '-' otherwise.  With fewer than two FILEs, assume -h." fullword ascii
      $s22 = "fread_unlocked" fullword ascii
      $s23 = "pcre2_config_8" fullword ascii
      $s24 = "pcre2_compile_8" fullword ascii
      $s25 = "pcre2_compile_context_free_8" fullword ascii
      $s26 = "pcre2_compile_context_create_8" fullword ascii
      $s27 = "pcre2_jit_compile_8" fullword ascii
      $s28 = "(?<!\\w)(?:invalid argument %s for %s" fullword ascii
      $s29 = "JIT internal error: %d" fullword ascii
      $s30 = "When FILE is '-', read standard input.  With no FILE, read '.' if" fullword ascii
      $s31 = "Usage: %s [OPTION]... PATTERNS [FILE]..." fullword ascii
      $s32 = "pcre2_set_compile_extra_options_8" fullword ascii
      $s33 = "AWAVAUD" fullword ascii
      $s34 = "%s: PCRE detected recurse loop" fullword ascii
      $s35 = "AWAVATD" fullword ascii
      $s36 = "%s: input file is also the output" fullword ascii
      $s37 = "%s: exceeded PCRE's backtracking limit" fullword ascii
      $s38 = "%s: exhausted PCRE JIT stack" fullword ascii
      $s39 = "%s: memory exhausted" fullword ascii
      $s40 = "%s: exceeded PCRE's nested backtracking limit" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      8 of them
}

rule false_negative_bins_nl {
   strings:
      $s1 = "Default options are: -bt -d'\\:' -fn -hn -i1 -l1 -n'rn' -s<TAB> -v1 -w6" fullword ascii
      $s2 = "  -h, --header-numbering=STYLE    use STYLE for numbering header lines" fullword ascii
      $s3 = "  -v, --starting-line-number=NUMBER  first line number for each section" fullword ascii
      $s4 = "invalid starting line number" fullword ascii
      $s5 = "invalid line number of blank lines" fullword ascii
      $s6 = "invalid line number field width" fullword ascii
      $s7 = "invalid line number increment" fullword ascii
      $s8 = "AVAUATU1" fullword ascii
      $s9 = "CC are two delimiter characters used to construct logical page delimiters;" fullword ascii
      $s10 = "Unmatched [, [^, [:, [., or [=" fullword ascii
      $s11 = "more than two characters, and also specifying the empty string (-d '')" fullword ascii
      $s12 = "line-increment" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "STYLE is one of:" fullword ascii
      $s14 = "539fef4789eac6a9ee5ed85e2e63bc46d220c7.debug" fullword ascii
      $s15 = "disables section matching." fullword ascii
      $s16 = "  -d, --section-delimiter=CC      use CC for logical page delimiters" fullword ascii
      $s17 = "  -s, --number-separator=STRING   add STRING after (possible) line number" fullword ascii
      $s18 = "join-blank-lines" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "number-format" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "  -f, --footer-numbering=STYLE    use STYLE for numbering footer lines" fullword ascii
      $s21 = "Write each FILE to standard output, with line numbers added." fullword ascii /* Goodware String - occured 2 times */
      $s22 = "Scott Bartram" fullword ascii /* Goodware String - occured 2 times */
      $s23 = "  -b, --body-numbering=STYLE      use STYLE for numbering body lines" fullword ascii
      $s24 = "FORMAT is one of:" fullword ascii /* Goodware String - occured 2 times */
      $s25 = "footer-numbering" fullword ascii /* Goodware String - occured 2 times */
      $s26 = "  -l, --join-blank-lines=NUMBER   group of NUMBER empty lines counted as one" fullword ascii
      $s27 = "invalid body numbering style: %s" fullword ascii /* Goodware String - occured 2 times */
      $s28 = "body-numbering" fullword ascii /* Goodware String - occured 2 times */
      $s29 = "invalid header numbering style: %s" fullword ascii /* Goodware String - occured 2 times */
      $s30 = "  -i, --line-increment=NUMBER     line number increment at each line" fullword ascii
      $s31 = "invalid line numbering format: %s" fullword ascii /* Goodware String - occured 2 times */
      $s32 = "header-numbering" fullword ascii /* Goodware String - occured 2 times */
      $s33 = "  -w, --number-width=NUMBER       use NUMBER columns for line numbers" fullword ascii
      $s34 = "number-separator" fullword ascii /* Goodware String - occured 2 times */
      $s35 = "  -p, --no-renumber               do not reset line numbers for each section" fullword ascii
      $s36 = "section-delimiter" fullword ascii /* Goodware String - occured 2 times */
      $s37 = "invalid footer numbering style: %s" fullword ascii /* Goodware String - occured 2 times */
      $s38 = "no-renumber" fullword ascii /* Goodware String - occured 2 times */
      $s39 = "h:b:f:v:i:pl:s:w:n:d:" fullword ascii /* Goodware String - occured 2 times */
      $s40 = "starting-line-number" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule false_negative_bins_cmp {
   strings:
      $s1 = "missing operand after '%s'" fullword ascii
      $s2 = "standard file descriptors" fullword ascii
      $s3 = "extra operand '%s'" fullword ascii
      $s4 = "invalid --bytes value '%s'" fullword ascii
      $s5 = "invalid --ignore-initial value '%s'" fullword ascii
      $s6 = "https://www.gnu.org/software/diffutils/" fullword ascii
      $s7 = "cmp: EOF on %s after byte %s, line %s" fullword ascii
      $s8 = "cmp: EOF on %s after byte %s, in line %s" fullword ascii
      $s9 = "program error" fullword ascii
      $s10 = "sigaltstack" fullword ascii
      $s11 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/diffutils.debug" fullword ascii
      $s12 = "If a FILE is '-' or missing, read standard input." fullword ascii
      $s13 = "cmp: EOF on %s which is empty" fullword ascii
      $s14 = "cmp: EOF on %s after byte %s" fullword ascii
      $s15 = "H;T$hu" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "xstrtol.c" fullword ascii
      $s17 = "gnulib sigsegv (stackoverflow_deinstall_handler)" fullword ascii
      $s18 = "/proc/self/maps" fullword ascii
      $s19 = "-l, --verbose              output byte numbers and differing byte values" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "The optional SKIP1 and SKIP2 specify the number of bytes to skip" fullword ascii /* Goodware String - occured 1 times */
      $s21 = "-v, --version              output version information and exit" fullword ascii /* Goodware String - occured 1 times */
      $s22 = "0f95207125b3af81df039981fee8e1cc7535e2.debug" fullword ascii
      $s23 = "//TRANSLH" fullword ascii
      $s24 = "-i, --ignore-initial=SKIP1:SKIP2  skip first SKIP1 bytes of FILE1 and" fullword ascii /* Goodware String - occured 1 times */
      $s25 = "at the beginning of each file (zero by default)." fullword ascii /* Goodware String - occured 1 times */
      $s26 = "-i, --ignore-initial=SKIP         skip first SKIP bytes of both inputs" fullword ascii /* Goodware String - occured 1 times */
      $s27 = "-n, --bytes=LIMIT          compare at most LIMIT bytes" fullword ascii /* Goodware String - occured 1 times */
      $s28 = "-s, --quiet, --silent      suppress all normal output" fullword ascii /* Goodware String - occured 1 times */
      $s29 = "-b, --print-bytes          print differing bytes" fullword ascii /* Goodware String - occured 1 times */
      $s30 = "AUAVSH" fullword ascii
      $s31 = "    --help                 display this help and exit" fullword ascii
      $s32 = "kB 1000, K 1024, MB 1,000,000, M 1,048,576," fullword ascii /* Goodware String - occured 2 times */
      $s33 = "SKIP values may be followed by the following multiplicative suffixes:" fullword ascii /* Goodware String - occured 2 times */
      $s34 = "%s %s differ: byte %s, line %s is %3o %s %3o %s" fullword ascii /* Goodware String - occured 2 times */
      $s35 = "GB 1,000,000,000, G 1,073,741,824, and so on for T, P, E, Z, Y." fullword ascii /* Goodware String - occured 2 times */
      $s36 = "print-bytes" fullword ascii /* Goodware String - occured 2 times */
      $s37 = "Compare two files byte by byte." fullword ascii /* Goodware String - occured 2 times */
      $s38 = "%s %s differ: char %s, line %s" fullword ascii /* Goodware String - occured 2 times */
      $s39 = "Usage: %s [OPTION]... FILE1 [FILE2 [SKIP1 [SKIP2]]]" fullword ascii /* Goodware String - occured 2 times */
      $s40 = "%*s %3o %-4s %3o %s" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_ptx {
   strings:
      $s1 = "error: regular expression has a match of length zero: %s" fullword ascii
      $s2 = "  -t, --typeset-mode               - not implemented -" fullword ascii
      $s3 = "baee6902524923bdd86a700adc2a477ea29cd4.debug" fullword ascii
      $s4 = "  or:  %s -G [OPTION]... [INPUT [OUTPUT]]" fullword ascii
      $s5 = "  -W, --word-regexp=REGEXP       use REGEXP to match each keyword" fullword ascii
      $s6 = "  -o, --only-file=FILE           read only word list from this FILE" fullword ascii
      $s7 = "  -i, --ignore-file=FILE         read ignore word list from FILE" fullword ascii
      $s8 = "  -G, --traditional              behave more like System V 'ptx'" fullword ascii
      $s9 = "AVAUATU1" fullword ascii
      $s10 = "Unmatched [, [^, [:, [., or [=" fullword ascii
      $s11 = "H;T$hu" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "//TRANSLH" fullword ascii
      $s13 = "lib/mbiter.h" fullword ascii
      $s14 = "lib/mbuiter.h" fullword ascii
      $s15 = "AF:GM:ORS:TW:b:i:fg:o:trw:" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "ois Pinard" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "baee6902524923bdd86a7" ascii
      $s18 = "baee6902524923bdd86a700adc2a477ea29cd4" ascii
      $s19 = "F. Pinard" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "  -w, --width=NUMBER             output width in columns, reference excluded" fullword ascii
      $s21 = "[.?!][]\"')}]*\\($\\|" fullword ascii /* Goodware String - occured 2 times */
      $s22 = "sentence-regexp" fullword ascii /* Goodware String - occured 2 times */
      $s23 = "\\|  \\)[ " fullword ascii /* Goodware String - occured 2 times */
      $s24 = "flag-truncation" fullword ascii /* Goodware String - occured 2 times */
      $s25 = "Output a permuted index, including context, of the words in the input files." fullword ascii /* Goodware String - occured 2 times */
      $s26 = "  -R, --right-side-refs          put references at right, not counted in -w" fullword ascii
      $s27 = "auto-reference" fullword ascii /* Goodware String - occured 2 times */
      $s28 = "  -b, --break-file=FILE          word break characters in this FILE" fullword ascii
      $s29 = "typeset-mode" fullword ascii /* Goodware String - occured 2 times */
      $s30 = "  -g, --gap-size=NUMBER          gap size in columns between output fields" fullword ascii
      $s31 = "%s (for regexp %s)" fullword ascii /* Goodware String - occured 2 times */
      $s32 = "break-file" fullword ascii /* Goodware String - occured 2 times */
      $s33 = "  -O, --format=roff              generate output as roff directives" fullword ascii
      $s34 = "  -T, --format=tex               generate output as TeX directives" fullword ascii
      $s35 = "  -r, --references               first field of each line is a reference" fullword ascii
      $s36 = "$%&#_{}\\" fullword ascii /* Goodware String - occured 2 times */
      $s37 = "Usage: %s [OPTION]... [INPUT]...   (without -G)" fullword ascii /* Goodware String - occured 2 times */
      $s38 = "invalid gap width: %s" fullword ascii /* Goodware String - occured 2 times */
      $s39 = "\\backslash{}" fullword ascii /* Goodware String - occured 2 times */
      $s40 = "gap-size" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule false_negative_bins_od {
   strings:
      $s1 = "  -N, --read-bytes=BYTES      limit dump to BYTES input bytes" fullword ascii
      $s2 = "  -S BYTES, --strings[=BYTES]  output strings of at least BYTES graphic chars;" fullword ascii
      $s3 = "  -w[BYTES], --width[=BYTES]  output BYTES bytes per output line;" fullword ascii
      $s4 = "fread_unlocked" fullword ascii
      $s5 = "invalid output address radix '%c'; it must be one character from [doxn]" fullword ascii
      $s6 = "  -s   same as -t d2, select decimal 2-byte units" fullword ascii
      $s7 = "  -f   same as -t fF, select floats" fullword ascii
      $s8 = "  -b   same as -t o1, select octal bytes" fullword ascii
      $s9 = "  -l   same as -t dL, select decimal longs" fullword ascii
      $s10 = "  -a   same as -t a,  select named characters, ignoring high-order bit" fullword ascii
      $s11 = "  -x   same as -t x2, select hexadecimal 2-byte units" fullword ascii
      $s12 = "  -i   same as -t dI, select decimal ints" fullword ascii
      $s13 = "__fread_unlocked_chk" fullword ascii
      $s14 = "  -o   same as -t o2, select octal 2-byte units" fullword ascii
      $s15 = "  -d   same as -t u2, select unsigned decimal 2-byte units" fullword ascii
      $s16 = "  -A, --address-radix=RADIX   output format for file offsets; RADIX is one" fullword ascii
      $s17 = "  or:  %s --traditional [OPTION]... [FILE] [[+]OFFSET[.][b] [+][LABEL][.][b]]" fullword ascii
      $s18 = "A(H;A0" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "%%*.%d%s" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "read_block" fullword ascii /* Goodware String - occured 1 times */
      $s21 = "Adding a z suffix to any type displays printable characters at the end of" fullword ascii
      $s22 = "invalid character '%c' in type string %s" fullword ascii
      $s23 = "compatibility mode supports at most one file" fullword ascii /* Goodware String - occured 1 times */
      $s24 = "SIZE is a number.  For TYPE in [doux], SIZE may also be C for" fullword ascii
      $s25 = "each output line." fullword ascii
      $s26 = "7f98772b55bd3d86a28eb0ef033cd0ab1193e3.debug" fullword ascii
      $s27 = "decode_format_string" fullword ascii /* Goodware String - occured 1 times */
      $s28 = "BYTES is hex with 0x or 0X prefix, and may have a multiplier suffix:" fullword ascii
      $s29 = "decode_one_format" fullword ascii /* Goodware String - occured 1 times */
      $s30 = "Binary prefixes can be used, too: KiB=K, MiB=M, and so on." fullword ascii
      $s31 = "bEGKkMmPTYZ0" fullword ascii /* Goodware String - occured 2 times */
      $s32 = "A:aBbcDdeFfHhIij:LlN:OoS:st:vw::Xx" fullword ascii /* Goodware String - occured 2 times */
      $s33 = "this system doesn't provide a %lu-byte floating point type" fullword ascii /* Goodware String - occured 2 times */
      $s34 = "Write an unambiguous representation, octal bytes by default," fullword ascii /* Goodware String - occured 2 times */
      $s35 = "concatenate them in the listed order to form the input." fullword ascii /* Goodware String - occured 2 times */
      $s36 = "skip-bytes" fullword ascii /* Goodware String - occured 2 times */
      $s37 = "at first byte printed, incremented when dump is progressing." fullword ascii /* Goodware String - occured 2 times */
      $s38 = "s != next" fullword ascii /* Goodware String - occured 2 times */
      $s39 = "cannot skip past end of combined input" fullword ascii /* Goodware String - occured 2 times */
      $s40 = "n_bytes_read == bytes_per_block" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_fmt {
   strings:
      $s1 = "get_paragraph" fullword ascii
      $s2 = "invalid width" fullword ascii
      $s3 = "The option -WIDTH is an abbreviated form of --width=DIGITS." fullword ascii /* Goodware String - occured 1 times */
      $s4 = "0123456789cstuw:p:g:" fullword ascii
      $s5 = "Usage: %s [-WIDTH] [OPTION]... [FILE]..." fullword ascii /* Goodware String - occured 1 times */
      $s6 = "word < word_limit" fullword ascii
      $s7 = "27a33507f57b32d2cbe099c1588299144077c3.debug" fullword ascii
      $s8 = "G(H;G0r" fullword ascii /* Goodware String - occured 2 times */
      $s9 = "Ross Paterson" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "  -w, --width=WIDTH         maximum line width (default of 75 columns)" fullword ascii
      $s11 = "split-only" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "option; use -w N instead" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "  -p, --prefix=STRING       reformat only lines beginning with STRING," fullword ascii
      $s14 = "crown-margin" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "  -g, --goal=WIDTH          goal width (default of 93% of width)" fullword ascii
      $s16 = "uniform-spacing" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "invalid option -- %c; -WIDTH is recognized only when it is the first" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "  -u, --uniform-spacing     one space between words, two after sentences" fullword ascii
      $s19 = "tagged-paragraph" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "  -c, --crown-margin        preserve indentation of first two lines" fullword ascii
      $s21 = "Reformat each paragraph in the FILE(s), writing to standard output." fullword ascii /* Goodware String - occured 2 times */
      $s22 = "  -s, --split-only          split long lines, but do not refill" fullword ascii
      $s23 = "  -t, --tagged-paragraph    indentation of first line different from second" fullword ascii
      $s24 = "closing standard input" fullword ascii /* Goodware String - occured 3 times */
      $s25 = "G(H;G0swH" fullword ascii
      $s26 = "G(H;G0s" fullword ascii
      $s27 = "27a33507f57b32d2cbe099c1588299144077c3" ascii
      $s28 = "G(H;G0sOH" fullword ascii
      $s29 = "0123456789c" ascii
      $s30 = "src/fmt.c" fullword ascii
      $s31 = "                              reattaching the prefix to reformatted lines" fullword ascii
      $s32 = "G(H;G0s.H" fullword ascii
      $s33 = "G(H;G0s'H" fullword ascii
      $s34 = "__memmove_chk" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_cat {
   strings:
      $s1 = "  %s f - g  Output f's contents, then standard input, then g's contents." fullword ascii
      $s2 = "  -b, --number-nonblank    number nonempty output lines, overrides -n" fullword ascii
      $s3 = "  -u                       (ignored)" fullword ascii
      $s4 = "  -v, --show-nonprinting   use ^ and M- notation, except for LFD and TAB" fullword ascii
      $s5 = "  -t                       equivalent to -vT" fullword ascii
      $s6 = "  -e                       equivalent to -vE" fullword ascii
      $s7 = "GLIBC_2.16" fullword ascii
      $s8 = "copy_file_range" fullword ascii
      $s9 = "GLIBC_2.27" fullword ascii
      $s10 = "aligned_alloc" fullword ascii
      $s11 = "  %s        Copy standard input to standard output." fullword ascii
      $s12 = "benstuvAET" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "  -s, --squeeze-blank      suppress repeated empty output lines" fullword ascii
      $s14 = "  -E, --show-ends          display $ at end of each line" fullword ascii
      $s15 = "show-ends" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "squeeze-blank" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "  -T, --show-tabs          display TAB characters as ^I" fullword ascii
      $s18 = "number-nonblank" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "%s: input file is output file" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "  -n, --number             number all output lines" fullword ascii
      $s21 = "9fcce36ca2f4d03cae6b3e13d12cbb74c413e8.debug" fullword ascii
      $s22 = "  -A, --show-all           equivalent to -vET" fullword ascii
      $s23 = "closing standard input" fullword ascii /* Goodware String - occured 3 times */
      $s24 = "show-nonprinting" fullword ascii /* Goodware String - occured 4 times */
      $s25 = "^M^?M-^I9.1" fullword ascii
      $s26 = "D$H9l$P" fullword ascii
      $s27 = "show-tabs" fullword ascii /* Goodware String - occured 5 times */
      $s28 = "Concatenate FILE(s) to standard output." fullword ascii
      $s29 = "9fcce36ca2f4d03cae6b3e13d12cbb74c413e8" ascii
      $s30 = "cannot do ioctl on %s" fullword ascii
      $s31 = "show-all" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_join {
   strings:
      $s1 = "E.g., use \"sort -k 1b,1\" if 'join' has no options," fullword ascii
      $s2 = "or use \"join -t ''\" if 'sort' has no options." fullword ascii
      $s3 = "When FILE1 or FILE2 (not both) is -, read standard input." fullword ascii
      $s4 = "      --header           treat the first line in each file as field headers," fullword ascii
      $s5 = "  -z, --zero-terminated  line delimiter is NUL, not newline" fullword ascii
      $s6 = "  -a FILENUM             also print unpairable lines from file FILENUM, where" fullword ascii
      $s7 = "  -t CHAR                use CHAR as input and output field separator" fullword ascii
      $s8 = "  -v FILENUM             like -a FILENUM, but suppress joined output lines" fullword ascii
      $s9 = "  -e STRING              replace missing (empty) input fields with STRING;" fullword ascii
      $s10 = "Note, comparisons honor the rules specified by 'LC_COLLATE'." fullword ascii
      $s11 = "  -o FORMAT              obey FORMAT while constructing output line" fullword ascii
      $s12 = "  -j FIELD               equivalent to '-1 FIELD -2 FIELD'" fullword ascii
      $s13 = "%s:%lu: is not sorted: %.*s" fullword ascii
      $s14 = "input is not in sorted order" fullword ascii
      $s15 = "923993b6b5dd068ff6e974dce5d35353c36f89.debug" fullword ascii
      $s16 = "If the input is not sorted and some lines cannot be joined, a" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "separated by CHAR.  If FORMAT is the keyword 'auto', then the first" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "line of each file determines the number of fields output for each line." fullword ascii /* Goodware String - occured 1 times */
      $s19 = "warning message will be given." fullword ascii /* Goodware String - occured 1 times */
      $s20 = "each being 'FILENUM.FIELD' or '0'.  Default FORMAT outputs the join field," fullword ascii
      $s21 = "standard output.  The default join field is the first, delimited by blanks." fullword ascii
      $s22 = "invalid field specifier: %s" fullword ascii /* Goodware String - occured 2 times */
      $s23 = "D$0t8H" fullword ascii /* Goodware String - occured 2 times */
      $s24 = "conflicting empty-field replacement strings" fullword ascii /* Goodware String - occured 2 times */
      $s25 = "from 1.  FORMAT is one or more comma or blank separated specifications," fullword ascii /* Goodware String - occured 2 times */
      $s26 = "invalid file number in field spec: %s" fullword ascii /* Goodware String - occured 2 times */
      $s27 = "nocheck-order" fullword ascii /* Goodware String - occured 2 times */
      $s28 = "the remaining fields from FILE1, the remaining fields from FILE2, all" fullword ascii /* Goodware String - occured 2 times */
      $s29 = "      --nocheck-order    do not check that the input is correctly sorted" fullword ascii
      $s30 = "For each pair of input lines with identical join fields, write a line to" fullword ascii /* Goodware String - occured 2 times */
      $s31 = "else fields are separated by CHAR.  Any FIELD is a field number counted" fullword ascii /* Goodware String - occured 2 times */
      $s32 = "Unless -t CHAR is given, leading blanks separate fields and are ignored," fullword ascii /* Goodware String - occured 2 times */
      $s33 = "Important: FILE1 and FILE2 must be sorted on the join fields." fullword ascii /* Goodware String - occured 2 times */
      $s34 = "both files cannot be standard input" fullword ascii /* Goodware String - occured 2 times */
      $s35 = "  -2 FIELD               join on this FIELD of file 2" fullword ascii
      $s36 = "incompatible join fields %lu, %lu" fullword ascii /* Goodware String - occured 2 times */
      $s37 = "invalid field number: %s" fullword ascii /* Goodware String - occured 2 times */
      $s38 = "      --check-order      check that the input is correctly sorted, even" fullword ascii
      $s39 = "  -1 FIELD               join on this FIELD of file 1" fullword ascii
      $s40 = "  -i, --ignore-case      ignore differences in case when comparing fields" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_mawk {
   strings:
      $s1 = "failed to exec %s -c %s" fullword ascii
      $s2 = "-W exec is incompatible with -f" fullword ascii
      $s3 = "    If no -f option is given, a \"--\" ends option processing; the following" fullword ascii
      $s4 = "    -W dump          show assembler-like listing of program and exit." fullword ascii
      $s5 = "j > 0 && fbankv[j - 1] != 0 && fbankv[j] == 0" fullword ascii
      $s6 = "resource exhaustion -- regular expression too large" fullword ascii
      $s7 = "                     command-line.  Multiple -f options are accepted." fullword ascii
      $s8 = "REcompile() - panic:  %s" fullword ascii
      $s9 = "%s: %s%sline %u: " fullword ascii
      $s10 = "regular expression compile failed (%s)" fullword ascii
      $s11 = "%s: run time error: " fullword ascii
      $s12 = "improper assignment: -v %s" fullword ascii
      $s13 = "mawk %d.%d%s %s" fullword ascii
      $s14 = "syntax error ^* or ^+" fullword ascii
      $s15 = "? ambiguous -W value: %s vs %s" fullword ascii
      $s16 = "    -W exec file     use file as program as well as last option." fullword ascii
      $s17 = "# frame-number" fullword ascii
      $s18 = "cmdefghijkl" fullword wide
      $s19 = "%s%sline %u: missing %c near %s" fullword ascii
      $s20 = "not enough arguments passed to %s(\"%s\")" fullword ascii
      $s21 = "    -f program-file  Program  text is read from file instead of from the" fullword ascii
      $s22 = "?bad cell type passed to compare" fullword ascii
      $s23 = "syntax error at or near /%s/" fullword ascii
      $s24 = "improper conversion(number %d) in %s(\"%s\")" fullword ascii
      $s25 = "illegal format assigned to %s: %s" fullword ascii
      $s26 = "f_post_inc" fullword ascii
      $s27 = "unexpected write error" fullword ascii
      $s28 = "f_post_dec" fullword ascii
      $s29 = "type in bi_getline" fullword ascii
      $s30 = "type clash or keyword" fullword ascii
      $s31 = "# regex %p" fullword ascii
      $s32 = "missing value for -W sprintf" fullword ascii
      $s33 = "    -W usage         show this message and exit." fullword ascii
      $s34 = "missing value for -W random" fullword ascii
      $s35 = "bad class -- [], [^] or [" fullword ascii
      $s36 = "aabbbbbbbbbbbbbbbbbbbcddeefff" ascii
      $s37 = "vacuous option: -W %s" fullword ascii
      $s38 = "cannot command line assign to %s" fullword ascii
      $s39 = "defghijkl" fullword wide
      $s40 = "efghijkl" fullword wide
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule false_negative_bins_less {
   strings:
      $s1 = "Home page: https://greenwoodsoftware.com/less" fullword ascii
      $s2 = "        or from within less by using the - or -- command." fullword ascii
      $s3 = "%s: line %d: %s%s" fullword ascii
      $s4 = "  f  ^F  ^V  SPACE  *  Forward  one window (or _" fullword ascii
      $s5 = "      Commands marked with * may be preceded by a number, _" fullword ascii
      $s6 = "Warning: \"%s\" exists; Overwrite, Append, Don't log, or Quit? " fullword ascii
      $s7 = "#commandI9E" fullword ascii
      $s8 = "** Obtain release builds from the web page below." fullword ascii
      $s9 = "        Each \"find close bracket\" command goes forward to the close bracket " fullword ascii
      $s10 = " is not a regular file (use -f to see it)" fullword ascii
      $s11 = "** and may not function correctly." fullword ascii
      $s12 = "** This is an EXPERIMENTAL build of the 'less' software," fullword ascii
      $s13 = "Use backslash escaping in command line parameters" fullword ascii
      $s14 = "Don't use backslash escaping in command line parameters" fullword ascii
      $s15 = "  -w  ........  --hilite-unread" fullword ascii
      $s16 = "LESSKEYIN_SYSTEM" fullword ascii
      $s17 = "LESSKEYIN" fullword ascii
      $s18 = "Overwrite, Append, Don't log, or Quit? (Type \"O\", \"A\", \"D\" or \"Q\") " fullword ascii
      $s19 = "  -p [_" fullword ascii
      $s20 = "  -t [_" fullword ascii
      $s21 = "  -o [_" fullword ascii
      $s22 = "  -j [_" fullword ascii
      $s23 = "  -k [_" fullword ascii
      $s24 = "  -z [_" fullword ascii
      $s25 = "                  Screen position of target lines." fullword ascii
      $s26 = "                  Search starts just after target line." fullword ascii
      $s27 = "  -x [_" fullword ascii
      $s28 = "  -h [_" fullword ascii
      $s29 = "Get size of each file" fullword ascii
      $s30 = "Don't get size of each file" fullword ascii
      $s31 = "  -b [_" fullword ascii
      $s32 = "  -y [_" fullword ascii
      $s33 = "r  .  --color=x" fullword ascii
      $s34 = "  F                    Forward forever; like \"tail -f\"." fullword ascii
      $s35 = "  z                 *  Forward  one window (and set window to _" fullword ascii
      $s36 = "  ESC-(  LeftArrow  *  Left  one half screen width (or _" fullword ascii
      $s37 = "  e  ^E  j  ^N  CR  *  Forward  one line   (or _" fullword ascii
      $s38 = "  d  ^D             *  Forward  one half-window (and set half-window to _" fullword ascii
      $s39 = "rscroll" fullword ascii
      $s40 = "  ESC-SPACE         *  Forward  one window, but don't stop at end-of-file." fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      8 of them
}

rule false_negative_bins_tee {
   strings:
      $s1 = "The default MODE for the -p option is 'warn-nopipe'." fullword ascii
      $s2 = "The default operation when --output-error is not specified, is to" fullword ascii
      $s3 = "  -p                        diagnose errors writing to non pipes" fullword ascii
      $s4 = "exit immediately on error writing to a pipe, and diagnose errors" fullword ascii
      $s5 = "warn-nopipe" fullword ascii
      $s6 = "exit-nopipe" fullword ascii
      $s7 = "writing to non pipe outputs." fullword ascii
      $s8 = "  warn-nopipe    diagnose errors writing to any output not a pipe" fullword ascii
      $s9 = "  exit-nopipe    exit on error writing to any output not a pipe" fullword ascii
      $s10 = "MODE determines behavior with write errors on the outputs:" fullword ascii
      $s11 = "--output-error" fullword ascii
      $s12 = "e2621d9e0c70ee5f3c68bdccc42fc78425798c.debug" fullword ascii
      $s13 = "      --output-error[=MODE]   set behavior on write error.  See MODE below" fullword ascii
      $s14 = "  warn           diagnose errors writing to any output" fullword ascii
      $s15 = "e2621d9e0c70ee5f3c68bdccc42fc78425798c" ascii
      $s16 = "  exit           exit on error writing to any output" fullword ascii
      $s17 = "  -i, --ignore-interrupts   ignore interrupt signals" fullword ascii
      $s18 = "ignore-interrupts" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "  -a, --append              append to the given FILEs, do not overwrite" fullword ascii
      $s20 = "Copy standard input to each FILE, and also to standard output." fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_dash {
   strings:
      $s1 = "dumped)" fullword ascii
      $s2 = " is a shell keyword" fullword ascii
      $s3 = " is a shell function" fullword ascii
      $s4 = " is a %sshell builtin" fullword ascii
      $s5 = "xvsnprintf failed" fullword ascii
      $s6 = "Usage: getopts optstring var [arg...]" fullword ascii
      $s7 = "sigsetmask" fullword ascii
      $s8 = "readdir64" fullword ascii
      $s9 = "6397ddffc3e384c505d7deab3bed190c884df9.debug" fullword ascii
      $s10 = "N@%.*s: is read only" fullword ascii
      $s11 = "Maximum function recursion depth (%d) reached" fullword ascii
      $s12 = "AVAUATS" fullword ascii
      $s13 = "AWAVAUE" fullword ascii
      $s14 = "AUATUSE" fullword ascii
      $s15 = " a tracked alias for" fullword ascii
      $s16 = "AWAVAUATE1" fullword ascii
      $s17 = "rtprio" fullword ascii
      $s18 = "redirection" fullword ascii /* Goodware String - occured 7 times */
      $s19 = "monitor" fullword ascii /* Goodware String - occured 99 times */
      $s20 = "process" fullword ascii /* Goodware String - occured 171 times */
      $s21 = "Running" fullword ascii /* Goodware String - occured 192 times */
      $s22 = "command" fullword ascii /* Goodware String - occured 524 times */
      $s23 = "RTMIN+6" fullword ascii
      $s24 = "RTMAX-13" fullword ascii
      $s25 = "RTMIN+2" fullword ascii
      $s26 = "RTMAX-4" fullword ascii
      $s27 = " is an alias for %s" fullword ascii
      $s28 = " (core dH" fullword ascii
      $s29 = "RTMIN+7" fullword ascii
      $s30 = "6397ddffc3e384c505d7deab3bed190c884df9" ascii
      $s31 = "RTMIN+5" fullword ascii
      $s32 = "RTMIN+12" fullword ascii
      $s33 = "RTMIN+1" fullword ascii
      $s34 = "RTMAX-10" fullword ascii
      $s35 = "RTMAX-5" fullword ascii
      $s36 = "RTMIN+4" fullword ascii
      $s37 = "RTMAX-3" fullword ascii
      $s38 = "RTMIN+11" fullword ascii
      $s39 = "RTMAX-7" fullword ascii
      $s40 = "RTMAX-14" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule false_negative_bins_ssh {
   strings:
      $s1 = "publickey-hostbound@openssh.com" fullword ascii
      $s2 = "publickey-hostbound-v00@openssh.com" fullword ascii
      $s3 = "UpdateHostKeys=ask is incompatible with remote command execution; disabling" fullword ascii
      $s4 = "Executing proxy dialer command: %.500s" fullword ascii
      $s5 = "hostkeys-prove-00@openssh.com" fullword ascii
      $s6 = "hostkeys-00@openssh.com" fullword ascii
      $s7 = "key(s) for %s%s%s exist under other names; skipping UserKnownHostsFile update" fullword ascii
      $s8 = "Executing command: '%.500s'" fullword ascii
      $s9 = "%s: Failed to set SELinux execution context for %s (in enforcing mode)" fullword ascii
      $s10 = "process_cmdline" fullword ascii
      $s11 = "missing hostkey loader" fullword ascii
      $s12 = "cancel-streamlocal-forward@openssh.com" fullword ascii
      $s13 = "forwarded-streamlocal@openssh.com" fullword ascii
      $s14 = "streamlocal-forward@openssh.com" fullword ascii
      $s15 = "ProxyCommand=- and ProxyUseFDPass are incompatible" fullword ascii
      $s16 = "remote forward %s for: listen %s%s%d, connect %s:%d" fullword ascii
      $s17 = "%s%s%s:%ld: Removed %s key for host %s" fullword ascii
      $s18 = "Cannot execute command-line and remote command." fullword ascii
      $s19 = "private key %s contents do not match public" fullword ascii
      $s20 = "Skipping %s key %s - corresponding algo not in PubkeyAcceptedAlgorithms" fullword ascii
      $s21 = "session-bind@openssh.com" fullword ascii
      $s22 = "login failed for always-auth key" fullword ascii
      $s23 = "knownhostscommand" fullword ascii
      $s24 = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" fullword ascii
      $s25 = "%.200s line %d: match exec '%.100s' error" fullword ascii
      $s26 = "%s: Failed to set SELinux execution context for %s" fullword ascii
      $s27 = "%s: Failed to get default SELinux security context for %s (in enforcing mode)" fullword ascii
      $s28 = "Read from remote host %s: %s" fullword ascii
      $s29 = "load_hostkeys_command" fullword ascii
      $s30 = "Host directive not supported as a command-line option" fullword ascii
      $s31 = "ssh_agent_bind_hostkey" fullword ascii
      $s32 = "KnownHostsCommand failed" fullword ascii
      $s33 = "host key found via KnownHostsCommand; disabling UpdateHostkeys" fullword ascii
      $s34 = "credentials updated - forcing rekey" fullword ascii
      $s35 = "login failed" fullword ascii
      $s36 = "      !args                                  Execute local command" fullword ascii
      $s37 = "channel %d: request tty %d, X %d, agent %d, subsys %d, term \"%s\", cmd \"%s\", env %u" fullword ascii
      $s38 = "expanded RemoteForward listen path '%s' -> '%s'" fullword ascii
      $s39 = "subprocess" fullword ascii
      $s40 = "bound agent to hostkey" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and
      8 of them
}

rule ssh_keygen {
   strings:
      $s1 = "%.24s processed %lu of %lu (%lu%%) in %s, ETA %s" fullword ascii
      $s2 = "%s: Failed to set SELinux execution context for %s (in enforcing mode)" fullword ascii
      $s3 = "%s%s%s:%ld: Removed %s key for host %s" fullword ascii
      $s4 = "session-bind@openssh.com" fullword ascii
      $s5 = "login failed for always-auth key" fullword ascii
      $s6 = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" fullword ascii
      $s7 = "%s: Failed to set SELinux execution context for %s" fullword ascii
      $s8 = "%s: Failed to get default SELinux security context for %s (in enforcing mode)" fullword ascii
      $s9 = "login failed" fullword ascii
      $s10 = "subprocess" fullword ascii
      $s11 = "Unsupported operation for -Y: \"%s\"" fullword ascii
      $s12 = "Failed to read v2 public key from \"%s\"" fullword ascii
      $s13 = "provider %s: manufacturerID <%s> cryptokiVersion %d.%d libraryDescription <%s> libraryVersion %d.%d" fullword ascii
      $s14 = "PKCS#11 login failed: PIN locked" fullword ascii
      $s15 = "%s command \"%s\" running as %s (flags 0x%x)" fullword ascii
      $s16 = "sk-ecdsa-sha2-nistp256@openssh.com" fullword ascii
      $s17 = "sk-ssh-ed25519@openssh.com" fullword ascii
      $s18 = "rsa-sha2-512-cert-v01@openssh.com" fullword ascii
      $s19 = "rsa-sha2-256-cert-v01@openssh.com" fullword ascii
      $s20 = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" fullword ascii
      $s21 = "PKCS#11 login failed: PIN incorrect" fullword ascii
      $s22 = "C_GetTokenInfo for provider %s slot %lu failed: %lu" fullword ascii
      $s23 = "sk-ssh-ed25519-cert-v01@openssh.com" fullword ascii
      $s24 = "PKCS#11 login failed: error %lu" fullword ascii
      $s25 = "PKCS#11 login failed: PIN length out of range" fullword ascii
      $s26 = "ssh-ed25519-cert-v01@openssh.com" fullword ascii
      $s27 = "restrict-destination-v00@openssh.com" fullword ascii
      $s28 = "chacha20-poly1305@openssh.com" fullword ascii
      $s29 = "sk-provider@openssh.com" fullword ascii
      $s30 = "process from line %lu from pipe" fullword ascii
      $s31 = "%s: Failed to get default SELinux security context for %s" fullword ascii
      $s32 = "%s:%ld: parse error in hostkeys file" fullword ascii
      $s33 = "%s: ssh_selinux_getctxbyname: security_getenforce() failed" fullword ascii
      $s34 = "sshkey_dump_ec_point" fullword ascii
      $s35 = "incorrect passphrase supplied to decrypt private key" fullword ascii
      $s36 = "setexeccon" fullword ascii
      $s37 = "agent refused operation" fullword ascii
      $s38 = "getseuserbyname" fullword ascii
      $s39 = "No private key found for public key \"%s\"" fullword ascii
      $s40 = "A resident key scoped to '%s' with user id '%s' already exists." fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule false_negative_bins_vipw {
   strings:
      $s1 = "%s: can not get previous SELinux process context: %s" fullword ascii
      $s2 = "configuration error - unknown item '%s' (notify administrator)" fullword ascii
      $s3 = "can not get previous SELinux process context: %s" fullword ascii
      $s4 = "%s: failed to drop privileges (%s)" fullword ascii
      $s5 = "configuration error - cannot parse %s value: '%s'" fullword ascii
      $s6 = "%s: invalid chroot path '%s', only absolute paths are supported." fullword ascii
      $s7 = "%s: cannot execute %s: %s" fullword ascii
      $s8 = "/etc/login.defs" fullword ascii
      $s9 = "LOGIN_STRING" fullword ascii
      $s10 = "LOGIN_KEEP_USERNAME" fullword ascii
      $s11 = "HUSHLOGIN_FILE" fullword ascii
      $s12 = "NOLOGINS_FILE" fullword ascii
      $s13 = "Please use the command '%s' to do so." fullword ascii
      $s14 = "LOGIN_PLAIN_PROMPT" fullword ascii
      $s15 = "LOGIN_RETRIES" fullword ascii
      $s16 = "cannot open login definitions %s [%s]" fullword ascii
      $s17 = "FAKE_SHELL" fullword ascii
      $s18 = "cannot read login definitions %s [%s]" fullword ascii
      $s19 = "%s: multiple --root options" fullword ascii
      $s20 = "sgetsgent" fullword ascii
      $s21 = "sgetspent" fullword ascii
      $s22 = "fgetsgent" fullword ascii
      $s23 = "getsgnam" fullword ascii
      $s24 = "%s: %s file write error: %s" fullword ascii
      $s25 = "%s: %s file stat error: %s" fullword ascii
      $s26 = "%s: %s: lock file already used (nlink: %u)" fullword ascii
      $s27 = "%s: lock %s already used by PID %lu" fullword ascii
      $s28 = "%s: %s file sync error: %s" fullword ascii
      $s29 = "%s: unable to chroot to directory %s: %s" fullword ascii
      $s30 = "LOG_UNKFAIL_ENAB" fullword ascii
      $s31 = "FAILLOG_ENAB" fullword ascii
      $s32 = "audit_log_user_avc_message" fullword ascii
      $s33 = "LOG_OK_LOGINS" fullword ascii
      $s34 = "%s: cannot get lock %s: %s" fullword ascii
      $s35 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/passwd.debug" fullword ascii
      $s36 = "USERDEL_CMD" fullword ascii
      $s37 = "unknown configuration item `%s'" fullword ascii
      $s38 = "%s: existing lock file %s without a PID" fullword ascii
      $s39 = "%s: %s returned with status %d" fullword ascii
      $s40 = "%s: existing lock file %s with an invalid PID '%s'" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_scp {
   strings:
      $s1 = "users-groups-by-id@openssh.com" fullword ascii
      $s2 = "target port not supported with two remote hosts and the -R option" fullword ascii
      $s3 = "Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)" fullword ascii
      $s4 = "subprocess" fullword ascii
      $s5 = "%s command \"%s\" running as %s (flags 0x%x)" fullword ascii
      $s6 = "expand-path@openssh.com" fullword ascii
      $s7 = "lsetstat@openssh.com" fullword ascii
      $s8 = "limits@openssh.com" fullword ascii
      $s9 = "Ensure the remote shell produces no output for non-interactive sessions." fullword ascii
      $s10 = "incorrect passphrase supplied to decrypt private key" fullword ascii
      $s11 = "Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"" fullword ascii
      $s12 = "Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) \"%s\"" fullword ascii
      $s13 = "do_get_users_groups_by_id" fullword ascii
      $s14 = "Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"" fullword ascii
      $s15 = "Server does not support limits@openssh.com extension" fullword ascii
      $s16 = "Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) \"%s\" to \"%s\"" fullword ascii
      $s17 = "sftp connection failed" fullword ascii
      $s18 = "usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]" fullword ascii
      $s19 = "Server does not support lsetstat@openssh.com extension" fullword ascii
      $s20 = "Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) \"%s\" to \"%s\"" fullword ascii
      $s21 = "target directory \"%s\" does not exist" fullword ascii
      $s22 = "%s: invalid target" fullword ascii
      $s23 = "agent refused operation" fullword ascii
      $s24 = "download remote \"%s\": server did not send permissions" fullword ascii
      $s25 = "remote readdir \"%s\" failed" fullword ascii
      $s26 = "%s: failed to configure tunnel (mode %d): %s" fullword ascii
      $s27 = "download %s: not a regular file" fullword ascii
      $s28 = "-oRemoteCommand=none" fullword ascii
      $s29 = "Couldn't open logfile %s: %s" fullword ascii
      $s30 = "fcntl(%d, F_GETFL): %s" fullword ascii
      $s31 = "could not load host key" fullword ascii
      $s32 = "no matching host key type found" fullword ascii
      $s33 = "key encrypted using unsupported cipher" fullword ascii
      $s34 = "stdio rpath wpath cpath fattr tty proc exec" fullword ascii
      $s35 = "Sending SSH2_FXP_EXTENDED(fsync@openssh.com)" fullword ascii
      $s36 = "Sent message limits@openssh.com I:%u" fullword ascii
      $s37 = "Sent message fsync@openssh.com I:%u" fullword ascii
      $s38 = "communication with agent failed" fullword ascii
      $s39 = "template string too short" fullword ascii
      $s40 = "download \"%s\": not a regular file" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 800KB and
      8 of them
}

rule false_negative_bins_sftp {
   strings:
      $s1 = "users-groups-by-id@openssh.com" fullword ascii
      $s2 = "Sending SSH2_FXP_EXTENDED(users-groups-by-id@openssh.com)" fullword ascii
      $s3 = "process_get" fullword ascii
      $s4 = "subprocess" fullword ascii
      $s5 = "%s command \"%s\" running as %s (flags 0x%x)" fullword ascii
      $s6 = "expand-path@openssh.com" fullword ascii
      $s7 = "lsetstat@openssh.com" fullword ascii
      $s8 = "limits@openssh.com" fullword ascii
      $s9 = "Ensure the remote shell produces no output for non-interactive sessions." fullword ascii
      $s10 = "incorrect passphrase supplied to decrypt private key" fullword ascii
      $s11 = "Sending SSH2_FXP_EXTENDED(statvfs@openssh.com) \"%s\"" fullword ascii
      $s12 = "Sending SSH2_FXP_EXTENDED(expand-path@openssh.com) \"%s\"" fullword ascii
      $s13 = "do_get_users_groups_by_id" fullword ascii
      $s14 = "Sending SSH2_FXP_EXTENDED(lsetstat@openssh.com) \"%s\"" fullword ascii
      $s15 = "Server does not support limits@openssh.com extension" fullword ascii
      $s16 = "Sending SSH2_FXP_EXTENDED(hardlink@openssh.com) \"%s\" to \"%s\"" fullword ascii
      $s17 = "Server does not support lsetstat@openssh.com extension" fullword ascii
      $s18 = "Sending SSH2_FXP_EXTENDED(posix-rename@openssh.com) \"%s\" to \"%s\"" fullword ascii
      $s19 = "agent refused operation" fullword ascii
      $s20 = "download remote \"%s\": server did not send permissions" fullword ascii
      $s21 = "remote readdir \"%s\" failed" fullword ascii
      $s22 = "%s: failed to configure tunnel (mode %d): %s" fullword ascii
      $s23 = "download %s: not a regular file" fullword ascii
      $s24 = "process_put" fullword ascii
      $s25 = "Couldn't open logfile %s: %s" fullword ascii
      $s26 = "fcntl(%d, F_GETFL): %s" fullword ascii
      $s27 = "could not load host key" fullword ascii
      $s28 = "no matching host key type found" fullword ascii
      $s29 = "key encrypted using unsupported cipher" fullword ascii
      $s30 = "Sending SSH2_FXP_EXTENDED(fsync@openssh.com)" fullword ascii
      $s31 = "Sent message limits@openssh.com I:%u" fullword ascii
      $s32 = "Sent message fsync@openssh.com I:%u" fullword ascii
      $s33 = "communication with agent failed" fullword ascii
      $s34 = "template string too short" fullword ascii
      $s35 = "download \"%s\": not a regular file" fullword ascii
      $s36 = "stat remote \"%s\" failed" fullword ascii
      $s37 = "Unable to resume download of \"%s\": server reordered requests" fullword ascii
      $s38 = "stat remote \"%s\" directory failed" fullword ascii
      $s39 = "read remote \"%s\" : %s" fullword ascii
      $s40 = "origin readdir \"%s\" failed" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 800KB and
      8 of them
}

rule ssh_agent {
   strings:
      $s1 = "publickey-hostbound-v00@openssh.com" fullword ascii
      $s2 = "usage: ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]" fullword ascii
      $s3 = "unable to make the process undumpable: %s" fullword ascii
      $s4 = "unexpected session ID (%zu listed) on signature request for target user %s with key %s %s" fullword ascii
      $s5 = "session-bind@openssh.com" fullword ascii
      $s6 = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" fullword ascii
      $s7 = "process_ext_session_bind" fullword ascii
      $s8 = "socketentry fd=%d, entry %zu %s, from hostkey %s %s to user %s hostkey %s %s" fullword ascii
      $s9 = "process_lock_agent" fullword ascii
      $s10 = "subprocess" fullword ascii
      $s11 = "%s command \"%s\" running as %s (flags 0x%x)" fullword ascii
      $s12 = "sk-ecdsa-sha2-nistp256@openssh.com" fullword ascii
      $s13 = "sk-ssh-ed25519@openssh.com" fullword ascii
      $s14 = "rsa-sha2-512-cert-v01@openssh.com" fullword ascii
      $s15 = "rsa-sha2-256-cert-v01@openssh.com" fullword ascii
      $s16 = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" fullword ascii
      $s17 = "sk-ssh-ed25519-cert-v01@openssh.com" fullword ascii
      $s18 = "ssh-ed25519-cert-v01@openssh.com" fullword ascii
      $s19 = "restrict-destination-v00@openssh.com" fullword ascii
      $s20 = "chacha20-poly1305@openssh.com" fullword ascii
      $s21 = "sk-provider@openssh.com" fullword ascii
      $s22 = "%s: entering hostname %s, requested key %s %s, %u keys avail" fullword ascii
      $s23 = "sshkey_dump_ec_point" fullword ascii
      $s24 = "incorrect passphrase supplied to decrypt private key" fullword ascii
      $s25 = "Confirm user presence for key %s %s%s%s" fullword ascii
      $s26 = "empty password not supported" fullword ascii
      $s27 = "public key authentication request for user \"%s\" to listed host" fullword ascii
      $s28 = "%s%s%s: adding %skey %s %s" fullword ascii
      $s29 = "agent refused operation" fullword ascii
      $s30 = "%s: failed to configure tunnel (mode %d): %s" fullword ascii
      $s31 = "{\"type\":\"webauthn.get\",\"challenge\":\"" fullword ascii
      $s32 = "exec(%s): %s" fullword ascii
      $s33 = "signed data matches public key userauth request" fullword ascii
      $s34 = "refusing use of destination-constrained key: mismatch between hostkey in request and most recently bound session" fullword ascii
      $s35 = "process_remove_all_identities" fullword ascii
      $s36 = "process_request_identities" fullword ascii
      $s37 = "process_remove_identity" fullword ascii
      $s38 = "process_sign_request2" fullword ascii
      $s39 = "process_extension" fullword ascii
      $s40 = "Couldn't open logfile %s: %s" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 1000KB and
      8 of them
}

rule false_negative_bins_agetty {
   strings:
      $s1 = " -E, --remote               use -r <hostname> for login(1)" fullword ascii
      $s2 = "%s: invalid character conversion for login name" fullword ascii
      $s3 = " -l, --login-program <file> specify login program" fullword ascii
      $s4 = " -H, --host <hostname>      specify login host" fullword ascii
      $s5 = "autologin" fullword ascii
      $s6 = " -o, --login-options <opts> options that are passed to login" fullword ascii
      $s7 = "%s%s (automatic login)" fullword ascii
      $s8 = "%s: invalid character 0x%x in login name" fullword ascii
      $s9 = " -t, --timeout <number>     login process timeout" fullword ascii
      $s10 = " -p, --login-pause          wait for any key before the login" fullword ascii
      $s11 = "/dev/%s: cannot set process group: %m" fullword ascii
      $s12 = "login-program" fullword ascii
      $s13 = "skip-login" fullword ascii
      $s14 = "/bin/login" fullword ascii
      $s15 = "[press ENTER to login]" fullword ascii
      $s16 = "login-pause" fullword ascii
      $s17 = "login-options" fullword ascii
      $s18 = "%s: failed to get terminal attributes: %m" fullword ascii
      $s19 = "     --chdir <directory>    chdir before the login" fullword ascii
      $s20 = "     --nice <number>        run login with this priority" fullword ascii
      $s21 = " -n, --skip-login           do not prompt for login" fullword ascii
      $s22 = "%s: can't exec %s: %m" fullword ascii
      $s23 = "%s: can't change process priority: %m" fullword ascii
      $s24 = "lightmagenta" fullword ascii
      $s25 = "nohostname" fullword ascii
      $s26 = "getttynam" fullword ascii
      $s27 = "failed to create reload file: %s: %m" fullword ascii
      $s28 = "/dev/%s: vhangup() failed: %m" fullword ascii
      $s29 = "/run/agetty.reload" fullword ascii
      $s30 = "failed to get terminal attributes: %m" fullword ascii
      $s31 = "versionsort" fullword ascii
      $s32 = "     --reload               reload prompts on running agetty instances" fullword ascii
      $s33 = "/dev/%s: cannot get controlling tty: %m" fullword ascii
      $s34 = " -a, --autologin <user>     login the specified user automatically" fullword ascii
      $s35 = "failed to set the %s environment variable" fullword ascii
      $s36 = "/dev/%s: not a character device" fullword ascii
      $s37 = "%s: not open for read/write" fullword ascii
      $s38 = "%s: read: %m" fullword ascii
      $s39 = "%s: failed to set terminal attributes: %m" fullword ascii
      $s40 = "%s: input overrun" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_diff {
   strings:
      $s1 = "missing operand after '%s'" fullword ascii
      $s2 = "standard file descriptors" fullword ascii
      $s3 = "extra operand '%s'" fullword ascii
      $s4 = "subsidiary program '%s' could not be invoked" fullword ascii
      $s5 = "    --from-file=FILE1           compare FILE1 to all operands;" fullword ascii
      $s6 = "    --to-file=FILE2             compare all operands to FILE2;" fullword ascii
      $s7 = "\\|%s: recursive directory loop" fullword ascii
      $s8 = "https://www.gnu.org/software/diffutils/" fullword ascii
      $s9 = "subsidiary program '%s' failed (exit status %d)" fullword ascii
      $s10 = "subsidiary program '%s' failed" fullword ascii
      $s11 = "program error" fullword ascii
      $s12 = "sigaltstack" fullword ascii
      $s13 = "-I, --ignore-matching-lines=RE  ignore changes where all lines match RE" fullword ascii
      $s14 = "unparsable value for --palette" fullword ascii
      $s15 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/diffutils.debug" fullword ascii
      $s16 = "invalid horizon length '%s'" fullword ascii
      $s17 = "Symbolic links %s and %s differ" fullword ascii
      $s18 = "invalid color '%s'" fullword ascii
      $s19 = "subsidiary program '%s' not found" fullword ascii
      $s20 = "If a FILE is '-', read standard input." fullword ascii
      $s21 = "invalid width '%s'" fullword ascii
      $s22 = "invalid tabsize '%s'" fullword ascii
      $s23 = "conflicting %s option value '%s'" fullword ascii
      $s24 = "invalid context length '%s'" fullword ascii
      $s25 = "    --suppress-common-lines   do not output common lines" fullword ascii
      $s26 = "    --horizon-lines=NUM  keep NUM lines of the common prefix and suffix" fullword ascii
      $s27 = "    --left-column             output only the left column of common lines" fullword ascii
      $s28 = "-l, --paginate                pass output through 'pr' to paginate it" fullword ascii
      $s29 = "fflush_unlocked" fullword ascii
      $s30 = "re_set_syntax" fullword ascii /* Goodware String - occured 1 times */
      $s31 = "H;T$hu" fullword ascii /* Goodware String - occured 1 times */
      $s32 = "gnulib sigsegv (stackoverflow_deinstall_handler)" fullword ascii
      $s33 = "/proc/self/maps" fullword ascii
      $s34 = "//TRANSLH" fullword ascii
      $s35 = "F(I;F0" fullword ascii /* Goodware String - occured 1 times */
      $s36 = "-Z, --ignore-trailing-space     ignore white space at line end" fullword ascii /* Goodware String - occured 1 times */
      $s37 = "-n, --rcs                     output an RCS format diff" fullword ascii /* Goodware String - occured 1 times */
      $s38 = "-t, --expand-tabs             expand tabs to spaces in output" fullword ascii /* Goodware String - occured 1 times */
      $s39 = "  LTYPE is 'old', 'new', or 'unchanged'.  GTYPE is LTYPE or 'changed'." fullword ascii
      $s40 = ": mbuiter.h" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule false_negative_bins_perl {
   strings:
      $x1 = "l&cwlextgocrpcmadlmaghbahexahomarmiavstbatkbhksbuhdcakmcanschamchrscpmncprtcwucyrldsrtgonggrekgujrguruhluwhmngzlkitskndalaoolatn" ascii
      $x2 = "DEBPKG:debian/fakeroot - Postpone LD_LIBRARY_PATH evaluation to the binary targets." fullword ascii
      $s3 = "DEBPKG:debian/errno_ver - https://bugs.debian.org/343351 Remove Errno version check due to upgrade problems with long-running pr" ascii
      $s4 = "DEBPKG:fixes/math_complex_doc_great_circle - https://bugs.debian.org/697567 [rt.cpan.org #114104] Math::Trig: clarify definition" ascii
      $s5 = "DEBPKG:fixes/math_complex_doc_great_circle - https://bugs.debian.org/697567 [rt.cpan.org #114104] Math::Trig: clarify definition" ascii
      $s6 = "DEBPKG:debian/hppa_op_optimize_workaround - https://bugs.debian.org/838613 Temporarily lower the optimization of op.c on hppa du" ascii
      $s7 = "%sExecution of %s aborted due to compilation errors." fullword ascii
      $s8 = "DEBPKG:debian/hppa_op_optimize_workaround - https://bugs.debian.org/838613 Temporarily lower the optimization of op.c on hppa du" ascii
      $s9 = "DEBPKG:fixes/io_socket_ip_ipv6 - Disable getaddrinfo(3) AI_ADDRCONFIG for localhost and IPv4 numeric addresses" fullword ascii
      $s10 = "DEBPKG:debian/usrmerge-realpath - https://bugs.debian.org/914128 Configure / libpth.U: use realpath --no-symlinks on Debian" fullword ascii
      $s11 = "DEBPKG:debian/usrmerge-lib64 - https://bugs.debian.org/914128 Configure / libpth.U: Do not adjust glibpth when /usr/lib64 is pre" ascii
      $s12 = "DEBPKG:debian/configure-regen - https://bugs.debian.org/762638 Regenerate Configure et al. after probe unit changes" fullword ascii
      $s13 = "DEBPKG:debian/squelch-locale-warnings - https://bugs.debian.org/508764 Squelch locale warnings in Debian package maintainer scri" ascii
      $s14 = "DEBPKG:debian/find_html2text - https://bugs.debian.org/640479 Configure CPAN::Distribution with correct name of html2text" fullword ascii
      $s15 = "DEBPKG:debian/usrmerge-lib64 - https://bugs.debian.org/914128 Configure / libpth.U: Do not adjust glibpth when /usr/lib64 is pre" ascii
      $s16 = "Using /u for '%.*s' instead of /%s in regex; marked by <-- HERE in m/%d%lu%4p <-- HERE %d%lu%4p/" fullword ascii
      $s17 = "Unexpected binary operator '%c' with no preceding operand in regex; marked by <-- HERE in m/%d%lu%4p <-- HERE %d%lu%4p/" fullword ascii
      $s18 = "DEBPKG:debian/makemaker-manext - https://bugs.debian.org/247370 Make EU::MakeMaker honour MANnEXT settings in generated manpage " ascii
      $s19 = "DEBPKG:debian/deprecate-with-apt - https://bugs.debian.org/747628 Point users to Debian packages of deprecated core modules" fullword ascii
      $s20 = " ???? - dump.c does not know how to handle this MG_LEN" fullword ascii
      $s21 = "DEBPKG:fixes/readline-stream-errors - [80c1f1e] [GH #6799] https://bugs.debian.org/1016369 only clear the stream error state in " ascii
      $s22 = "DEBPKG:fixes/x32-io-msg-skip - https://bugs.debian.org/922609 Skip io/msg.t on x32 due to broken System V message queues" fullword ascii
      $s23 = "DEBPKG:fixes/math_complex_doc_angle_units - https://bugs.debian.org/731505 [rt.cpan.org #114106] Math::Trig: document angle unit" ascii
      $s24 = "DEBPKG:fixes/readline-stream-errors - [80c1f1e] [GH #6799] https://bugs.debian.org/1016369 only clear the stream error state in " ascii
      $s25 = "DEBPKG:debian/disable-stack-check - https://bugs.debian.org/902779 [GH #16607] Disable debugperl stack extension checks for bina" ascii
      $s26 = "DEBPKG:debian/prune_libs - https://bugs.debian.org/128355 Prune the list of libraries wanted to what we actually need." fullword ascii
      $s27 = "DEBPKG:debian/makemaker-pasthru - https://bugs.debian.org/758471 Pass LD settings through to subdirectories" fullword ascii
      $s28 = "DEBPKG:fixes/document_makemaker_ccflags - https://bugs.debian.org/628522 [rt.cpan.org #68613] Document that CCFLAGS should inclu" ascii
      $s29 = "  -u                    dump core after parsing program" fullword ascii
      $s30 = "DEBPKG:debian/errno_ver - https://bugs.debian.org/343351 Remove Errno version check due to upgrade problems with long-running pr" ascii
      $s31 = "DEBPKG:fixes/readline-stream-errors-test - [0b60216] [GH #6799] https://bugs.debian.org/1016369 test that <> doesn't clear the s" ascii
      $s32 = "DEBPKG:fixes/math_complex_doc_angle_units - https://bugs.debian.org/731505 [rt.cpan.org #114106] Math::Trig: document angle unit" ascii
      $s33 = "DEBPKG:fixes/math_complex_doc_see_also - https://bugs.debian.org/697568 [rt.cpan.org #114105] Math::Trig: add missing SEE ALSO" fullword ascii
      $s34 = "DEBPKG:fixes/readline-stream-errors-test - [0b60216] [GH #6799] https://bugs.debian.org/1016369 test that <> doesn't clear the s" ascii
      $s35 = "DEBPKG:debian/disable-stack-check - https://bugs.debian.org/902779 [GH #16607] Disable debugperl stack extension checks for bina" ascii
      $s36 = "DEBPKG:fixes/CVE-2023-47038 - [7047915] https://bugs.debian.org/1056746 Fix read/write past buffer end: perl-security#140" fullword ascii
      $s37 = "Attempt to free nonexistent shared string '%s'%s, Perl interpreter: 0x%p" fullword ascii
      $s38 = "Useless (%s%c) - %suse /%c modifier in regex; marked by <-- HERE in m/%d%lu%4p <-- HERE %d%lu%4p/" fullword ascii
      $s39 = "%d%lu%4p is forbidden - matches null string many times in regex; marked by <-- HERE in m/%d%lu%4p <-- HERE %d%lu%4p/" fullword ascii
      $s40 = "Perl_my_mkstemp_cloexec" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 11000KB and
      1 of ($x*) and 4 of them
}

rule false_negative_bins_debugfs {
   strings:
      $s1 = "Dumping descriptor block, sequence %u, at block %u:" fullword ascii
      $s2 = "%s: Usage: logdump [-acsOS] [-n<num_trans>] [-b<block>] [-i<filespec>]" fullword ascii
      $s3 = "Dumping revoke block, sequence %u, at block %u:" fullword ascii
      $s4 = "while dumping link destination" fullword ascii
      $s5 = "while opening %s for logdump" fullword ascii
      $s6 = "while dumping %s" fullword ascii
      $s7 = "Recursively dump a directory to the native filesystem" fullword ascii
      $s8 = "Usage: block_dump [-x] [-f inode] block_num" fullword ascii
      $s9 = "Usage: inode_dump [-b]|[-e] <file>" fullword ascii
      $s10 = "Usage: dump_extents [-n] [-l] file" fullword ascii
      $s11 = "Usage: dump_inode [-p] <file> <output_file>" fullword ascii
      $s12 = "%s fields supported by the %s command:" fullword ascii
      $s13 = "((hash_size) != 0 && (((hash_size) & ((hash_size) - 1)) == 0))" fullword ascii
      $s14 = "[ERROR] %s:%d:%s: while getting next inode. ret=%ld" fullword ascii
      $s15 = "while opening %s for dump_inode" fullword ascii
      $s16 = "Root node dump:" fullword ascii
      $s17 = "while closing %s for dump_inode" fullword ascii
      $s18 = "Bad log counts number - %s" fullword ascii
      $s19 = "Dump a hash-indexed directory" fullword ascii
      $s20 = "*** Fast Commit Area ***" fullword ascii
      $s21 = "[ERROR] %s:%d:%s: Inserting already present quota entry (block %u)." fullword ascii
      $s22 = "[ERROR] %s:%d:%s: ex2fs_read_inode failed" fullword ascii
      $s23 = "[ERROR] %s:%d:%s: ext2fs_file_read failed: %ld" fullword ascii
      $s24 = "JBD2: IO error %d recovering block %ld in log" fullword ascii
      $s25 = "JBD2: error %d scanning journal" fullword ascii
      $s26 = "Invalid inode number - '%s'" fullword ascii
      $s27 = "Usage: %s [-b blocksize] [-s superblock] [-f cmd_file] [-R request] [-d data_source_device] [-i] [-n] [-D] [-V] [[-w] [-z undo_f" ascii
      $s28 = "The -d option is only valid when reading an e2image file" fullword ascii
      $s29 = "JBD2: IO error %d recovering block %lu in log" fullword ascii
      $s30 = "Usage: %s [-b blocksize] [-s superblock] [-f cmd_file] [-R request] [-d data_source_device] [-i] [-n] [-D] [-V] [[-w] [-z undo_f" ascii
      $s31 = "%s: Usage: %s <file>" fullword ascii
      $s32 = "%s: Usage: %s [-f outfile]|[-xVC] [-r] <file> <attr>" fullword ascii
      $s33 = "dump_inode" fullword ascii
      $s34 = "dump_journal" fullword ascii
      $s35 = "<hexdump>" fullword ascii
      $s36 = "Dump contents of a block" fullword ascii
      $s37 = "dump_mmp" fullword ascii
      $s38 = "dump_file" fullword ascii
      $s39 = "block_dump" fullword ascii
      $s40 = "htree_dump_leaf_inode" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 700KB and
      8 of them
}

rule false_negative_bins_bzip2 {
   strings:
      $s1 = "   -t --test           test compressed file integrity" fullword ascii
      $s2 = "   (3) A bug in the compiler used to create this executable" fullword ascii
      $s3 = "   (2) A bug in the compiler used to create this executable" fullword ascii
      $s4 = "   -d --decompress     force decompression" fullword ascii
      $s5 = "   -z --compress       force compression" fullword ascii
      $s6 = "This is a BUG.  Please report it to:" fullword ascii
      $s7 = "   -s --small          use less memory (at most 2500k)" fullword ascii
      $s8 = "18f4acf8a1ac4fadbd4550b9a99eff9aeebdb1.debug" fullword ascii
      $s9 = "   -f --force          overwrite existing output files" fullword ascii
      $s10 = " no data compressed." fullword ascii
      $s11 = "bzip2-devel@sourceware.org" fullword ascii
      $s12 = "   usage: %s [flags and input files in any order]" fullword ascii
      $s13 = "   -h --help           print this message" fullword ascii
      $s14 = "   -k --keep           keep (don't delete) input files" fullword ascii
      $s15 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/bzip2.debug" fullword ascii
      $s16 = "   -c --stdout         output to standard out" fullword ascii
      $s17 = "   -v --verbose        be verbose (a 2nd -v gives more)" fullword ascii
      $s18 = "  %s: " fullword ascii
      $s19 = "       failed to detect this.  Try bzip2 -tvv my_file.bz2." fullword ascii
      $s20 = "   -L --license        display software version & license" fullword ascii
      $s21 = "   -V --version        display software version & license" fullword ascii
      $s22 = "   -q --quiet          suppress noncritical error messages" fullword ascii
      $s23 = "   If invoked as `bzip2', default action is to compress." fullword ascii
      $s24 = "   or (2), feel free to report it to: bzip2-devel@sourceware.org." fullword ascii
      $s25 = "   or (3), feel free to report it to: bzip2-devel@sourceware.org." fullword ascii
      $s26 = "remove" fullword ascii /* Goodware String - occured 588 times */
      $s27 = "libbz2.so.1.0" fullword ascii
      $s28 = "18f4acf8a1ac4fadbd4550b9a99eff9aeebdb1" ascii
      $s29 = "lstat64" fullword ascii /* Goodware String - occured 2 times */
      $s30 = "fopen64" fullword ascii /* Goodware String - occured 2 times */
      $s31 = "   short flags, so `-v -4' means the same as -v4 or -4v, &c." fullword ascii
      $s32 = "   --best              alias for -9" fullword ascii
      $s33 = "   (3) A real bug in bzip2 -- I hope this should never be the case." fullword ascii
      $s34 = "   (4) A real bug in bzip2 -- I hope this should never be the case." fullword ascii
      $s35 = "   --fast              alias for -1" fullword ascii
      $s36 = "   The user's manual, Section 4.3, has more info on (1) and (2)." fullword ascii
      $s37 = "   The user's manual, Section 4.3, has more info on (2) and (3)." fullword ascii
      $s38 = "   bug report should have.  If the manual is available on your" fullword ascii
      $s39 = "   Section 4.3 of the user's manual describes the info a useful" fullword ascii
      $s40 = "   system, please try and read it before mailing me.  If you don't" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_ln {
   strings:
      $s1 = "Usage: %s [OPTION]... [-T] TARGET LINK_NAME" fullword ascii
      $s2 = "  or:  %s [OPTION]... -t DIRECTORY TARGET..." fullword ascii
      $s3 = "  -t, --target-directory=DIRECTORY  specify the DIRECTORY in which to create" fullword ascii
      $s4 = "  -L, --logical               dereference TARGETs that are symbolic links" fullword ascii
      $s5 = "getrandom" fullword ascii
      $s6 = "  -T, --no-target-directory   treat LINK_NAME as a normal file always" fullword ascii
      $s7 = "  -d, -F, --directory         allow the superuser to attempt to hard link" fullword ascii
      $s8 = "  or:  %s [OPTION]... TARGET... DIRECTORY" fullword ascii
      $s9 = "  or:  %s [OPTION]... TARGET" fullword ascii
      $s10 = "The backup suffix is '~', unless set with --suffix or SIMPLE_BACKUP_SUFFIX." fullword ascii
      $s11 = "rpmatch" fullword ascii
      $s12 = "  -S, --suffix=SUFFIX         override the usual backup suffix" fullword ascii
      $s13 = "failed to access %s" fullword ascii
      $s14 = "  -b                          like --backup but does not accept an argument" fullword ascii
      $s15 = "AWAVAUE" fullword ascii
      $s16 = "generating relative path" fullword ascii
      $s17 = "renameat2" fullword ascii
      $s18 = "%s%s%s %c> %s" fullword ascii
      $s19 = "                                system restrictions, even for the superuser)" fullword ascii
      $s20 = "backup" fullword ascii /* Goodware String - occured 74 times */
      $s21 = "GLIBC_2.28" fullword ascii
      $s22 = "CuXXXXXX" fullword ascii
      $s23 = "target %s" fullword ascii /* Goodware String - occured 1 times */
      $s24 = "cannot do --relative without --symbolic" fullword ascii
      $s25 = "behavior when a TARGET is a symbolic link, defaulting to %s." fullword ascii /* Goodware String - occured 1 times */
      $s26 = "failed to create hard link to %.0s%s" fullword ascii /* Goodware String - occured 1 times */
      $s27 = "When creating hard links, each TARGET must exist.  Symbolic links" fullword ascii /* Goodware String - occured 1 times */
      $s28 = "failed to create hard link %s => %s" fullword ascii /* Goodware String - occured 1 times */
      $s29 = "can hold arbitrary text; if later resolved, a relative link is" fullword ascii /* Goodware String - occured 1 times */
      $s30 = "By default, each destination (name of new link) should not already exist." fullword ascii /* Goodware String - occured 1 times */
      $s31 = "interpreted in relation to its parent directory." fullword ascii /* Goodware String - occured 1 times */
      $s32 = "failed to create symbolic link %s -> %s" fullword ascii /* Goodware String - occured 1 times */
      $s33 = "bdfinrst:vFLPS:T" fullword ascii
      $s34 = "failed to create hard link %s" fullword ascii /* Goodware String - occured 1 times */
      $s35 = "cannot combine --target-directory and --no-target-directory" fullword ascii /* Goodware String - occured 1 times */
      $s36 = "failed to create symbolic link %s" fullword ascii /* Goodware String - occured 1 times */
      $s37 = "Using -s ignores -L and -P.  Otherwise, the last option specified controls" fullword ascii /* Goodware String - occured 1 times */
      $s38 = "  none, off       never make backups (even if --backup is given)" fullword ascii
      $s39 = "%s: replace %s? " fullword ascii /* Goodware String - occured 2 times */
      $s40 = "In the 1st form, create a link to TARGET with the name LINK_NAME." fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_iconv {
   strings:
      $s1 = "the FROM and TO command line parameters.  One coded character set can be" fullword ascii
      $s2 = "failed to start conversion processing" fullword ascii
      $s3 = "list all known coded character sets" fullword ascii
      $s4 = "The following list contains all the coded character sets known.  This does" fullword ascii
      $s5 = "conversion to `%s' is not supported" fullword ascii
      $s6 = "internal error (illegal descriptor)" fullword ascii
      $s7 = "conversion from `%s' is not supported" fullword ascii
      $s8 = "conversion from `%s' to `%s' is not supported" fullword ascii
      $s9 = "conversions from `%s' and to `%s' are not supported" fullword ascii
      $s10 = "syntax error in prolog: %s" fullword ascii
      $s11 = "error while reading the input" fullword ascii
      $s12 = "iconv %s%s" fullword ascii
      $s13 = "<http://www.debian.org/Bugs/>" fullword ascii
      $s14 = "error while closing input `%s'" fullword ascii
      $s15 = "syntax error in %s definition: %s" fullword ascii
      $s16 = "%s: error in state machine" fullword ascii
      $s17 = "failed to read locale!" fullword ascii
      $s18 = "character map `%s' is not ASCII compatible, locale not ISO C compliant [--no-warnings=ascii]" fullword ascii
      $s19 = "__gconv_get_modules_db" fullword ascii
      $s20 = "character sets with locking states are not supported" fullword ascii
      $s21 = "incomplete character or shift sequence at end of buffer" fullword ascii
      $s22 = "__dcgettext" fullword ascii
      $s23 = "error while closing output file" fullword ascii
      $s24 = "__gconv_get_alias_db" fullword ascii
      $s25 = "conversion stopped due to problem in writing the output" fullword ascii
      $s26 = "failed to restore %s locale!" fullword ascii
      $s27 = "readdir64" fullword ascii
      $s28 = "(char *) outbuf + outlen == outptr" fullword ascii
      $s29 = "/usr/share/i18n/charmaps" fullword ascii
      $s30 = "unknown character `%s'" fullword ascii
      $s31 = "posix_spawn_file_actions_addclose" fullword ascii
      $s32 = ".relr.dyn" fullword ascii
      $s33 = "value for %s must be an integer" fullword ascii
      $s34 = "value for <%s> must be 1 or greater" fullword ascii
      $s35 = "[error] %s" fullword ascii
      $s36 = "argument to <%s> must be a single character" fullword ascii
      $s37 = "3dfabbac902f14f28c61035b397a590ffad886.debug" fullword ascii
      $s38 = "charmap_conversion" fullword ascii
      $s39 = "GLIBC_PRIVATE" fullword ascii
      $s40 = "character map file `%s' not found" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_split {
   strings:
      $s1 = "      --filter=COMMAND    write to shell COMMAND; file name is $FILE" fullword ascii
      $s2 = "  -e, --elide-empty-files  do not generate empty output files with '-n'" fullword ascii
      $s3 = "Usage: %s [OPTION]... [FILE [PREFIX]]" fullword ascii
      $s4 = "  -x                      use hex suffixes starting at 0, not alphabetic" fullword ascii
      $s5 = "  -d                      use numeric suffixes starting at 0, not alphabetic" fullword ascii
      $s6 = "%s: invalid start value for hexadecimal suffix" fullword ascii
      $s7 = "invalid chunk number" fullword ascii
      $s8 = "empty record separator" fullword ascii
      $s9 = "invalid number of chunks" fullword ascii
      $s10 = "  -a, --suffix-length=N   generate suffixes of length N (default %d)" fullword ascii
      $s11 = "invalid suffix length" fullword ascii
      $s12 = "multiple separator characters specified" fullword ascii
      $s13 = "GLIBC_2.16" fullword ascii
      $s14 = "aligned_alloc" fullword ascii
      $s15 = "__libc_current_sigrtmax" fullword ascii
      $s16 = "__libc_current_sigrtmin" fullword ascii
      $s17 = "failed to create pipe" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "closing prior pipe" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "with FILE=%s, exit %d from command: %s" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "closing output pipe" fullword ascii /* Goodware String - occured 1 times */
      $s21 = "lines_chunk_split" fullword ascii /* Goodware String - occured 1 times */
      $s22 = "9104ef22f050e16f59a86cf3306c37ff51d4bc.debug" fullword ascii
      $s23 = "next_file_name" fullword ascii
      $s24 = "hex-suffixes" fullword ascii
      $s25 = "additional-suffix" fullword ascii
      $s26 = "The SIZE argument is an integer and optional unit (example: 10K is 10*1024)." fullword ascii
      $s27 = "failed to close input pipe" fullword ascii /* Goodware String - occured 1 times */
      $s28 = "--filter does not process a chunk extracted to stdout" fullword ascii /* Goodware String - occured 1 times */
      $s29 = "default size is 1000 lines, and default PREFIX is 'x'." fullword ascii
      $s30 = "failed to run command: \"%s -c %s\"" fullword ascii /* Goodware String - occured 1 times */
      $s31 = "bytes_chunk_extract" fullword ascii /* Goodware String - occured 1 times */
      $s32 = "multi-character separator %s" fullword ascii
      $s33 = "%s would overwrite input; aborting" fullword ascii
      $s34 = "waiting for child process" fullword ascii /* Goodware String - occured 1 times */
      $s35 = "output file suffixes exhausted" fullword ascii /* Goodware String - occured 1 times */
      $s36 = "%s: cannot determine file size" fullword ascii /* Goodware String - occured 1 times */
      $s37 = "invalid IO block size" fullword ascii
      $s38 = "src/split.c" fullword ascii
      $s39 = "k && n && k <= n && n <= file_size" fullword ascii /* Goodware String - occured 1 times */
      $s40 = "the suffix length needs to be at least %lu" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_env {
   strings:
      $s1 = "failed to get signal process mask" fullword ascii
      $s2 = "failed to set signal process mask" fullword ascii
      $s3 = "  -S, --split-string=S  process and split S into separate arguments;" fullword ascii
      $s4 = "must specify command with --chdir (-C)" fullword ascii
      $s5 = "  -v, --debug          print verbose information for each processing step" fullword ascii
      $s6 = "failed to get signal action for signal %d" fullword ascii
      $s7 = "invalid option -- '%c'" fullword ascii
      $s8 = "executing: %s" fullword ascii
      $s9 = "use -[v]S to pass options in shebang lines" fullword ascii
      $s10 = "Reset signal %s (%d) to %s%s" fullword ascii
      $s11 = "      --block-signal[=SIG]    block delivery of SIG signal(s) to COMMAND" fullword ascii
      $s12 = "SIG may be a signal name like 'PIPE', or a signal number like '13'." fullword ascii
      $s13 = "only ${VARNAME} expansion is supported, error at: %s" fullword ascii
      $s14 = "  -i, --ignore-environment  start with an empty environment" fullword ascii
      $s15 = "split -S:  %s" fullword ascii
      $s16 = "'\\c' must not appear in double-quoted -S string" fullword ascii
      $s17 = "no terminating quote in -S string" fullword ascii
      $s18 = "invalid sequence '\\%c' in -S" fullword ascii
      $s19 = "%-10s (%2d): %s%s%s" fullword ascii
      $s20 = "invalid backslash at end of string in -S" fullword ascii
      $s21 = "expanding ${%s} into %s" fullword ascii
      $s22 = "failed to set signal action for signal %d" fullword ascii
      $s23 = "comma-separated." fullword ascii
      $s24 = "signal %s (%d) mask set to %s" fullword ascii
      $s25 = "replacing ${%s} with null string" fullword ascii
      $s26 = " (failure ignored)" fullword ascii
      $s27 = "cleaning environ" fullword ascii
      $s28 = "DEFAULT" fullword ascii /* Goodware String - occured 381 times */
      $s29 = "Assaf Gordon" fullword ascii
      $s30 = "__libc_current_sigrtmax" fullword ascii
      $s31 = "__libc_current_sigrtmin" fullword ascii
      $s32 = "cannot change directory to %s" fullword ascii /* Goodware String - occured 1 times */
      $s33 = "cannot specify --null (-0) with command" fullword ascii /* Goodware String - occured 1 times */
      $s34 = "default-signal" fullword ascii
      $s35 = "cannot set %s" fullword ascii /* Goodware String - occured 1 times */
      $s36 = "                        used to pass multiple arguments on shebang lines" fullword ascii
      $s37 = "UNBLOCK" fullword ascii /* Goodware String - occured 1 times */
      $s38 = "list-signal-handling" fullword ascii
      $s39 = "cannot unset %s" fullword ascii /* Goodware String - occured 1 times */
      $s40 = "20aed1e513ad653e002bcb7fd80c9bbb686f62.debug" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule ldconfig {
   strings:
      $s1 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii
      $s2 = "%s: IFUNC symbol '%s' referenced in '%s' is defined in the executable and creates an unsatisfiable circular dependency." fullword ascii
      $s3 = "glibc.pthread.mutex_spin_count" fullword ascii
      $s4 = "PTHREAD_MUTEX_TYPE (mutex) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s5 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s6 = "__pthread_mutex_unlock_usercnt" fullword ascii
      $s7 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* hex encoded string '3333' */
      $s8 = "Only process directories specified on the command line.  Don't build cache." fullword ascii
      $s9 = "Unexpected error %d on netlink descriptor %d (address family %d)." fullword ascii
      $s10 = "getpublickey" fullword ascii
      $s11 = "getsecretkey" fullword ascii
      $s12 = "pthread_mutex_lock.c" fullword ascii
      $s13 = "__pthread_mutex_lock_full" fullword ascii
      $s14 = "pthread_mutex_unlock.c" fullword ascii
      $s15 = "relocation processing: %s%s" fullword ascii
      $s16 = "___pthread_mutex_lock" fullword ascii
      $s17 = "%s: line %d: bad command `%s'" fullword ascii
      $s18 = "glibc.cpu.x86_non_temporal_threshold" fullword ascii
      $s19 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
      $s20 = "EHWPOISON" fullword ascii
      $s21 = "Unexpected error %d on netlink descriptor %d." fullword ascii
      $s22 = "Unexpected netlink response of size %zd on descriptor %d (address family %d)" fullword ascii
      $s23 = "failed to allocate memory to process tunables" fullword ascii
      $s24 = "/proc/self/loginuid" fullword ascii
      $s25 = "*** %s ***: terminated" fullword ascii
      $s26 = "(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned l" ascii
      $s27 = "__nss_database_fork_subprocess" fullword ascii
      $s28 = "mutex->__data.__owner == 0" fullword ascii
      $s29 = "ELF load command address/offset not page-aligned" fullword ascii
      $s30 = "headmap.len == archive_stat.st_size" fullword ascii
      $s31 = "EKEYEXPIRED" fullword ascii
      $s32 = "gethostbyname_r" fullword ascii
      $s33 = "gethostbyaddr_r" fullword ascii
      $s34 = "gethostent_r" fullword ascii
      $s35 = "gethostbyaddr2_r" fullword ascii
      $s36 = "gethostbyname3_multi" fullword ascii
      $s37 = "gethostbyname4_r" fullword ascii
      $s38 = "gethostbyname3_r" fullword ascii
      $s39 = "_nss_files_gethostbyname4_r" fullword ascii
      $s40 = "gethostbyname2_r" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and
      8 of them
}

rule false_negative_bins_ar {
   strings:
      $s1 = "  --target=BFDNAME - specify the target object format as BFDNAME" fullword ascii
      $s2 = "  --output=DIRNAME - specify the output directory for extraction operations" fullword ascii
      $s3 = "bfd_set_default_target" fullword ascii
      $s4 = "bfd_target_list" fullword ascii
      $s5 = "bfd_find_target" fullword ascii
      $s6 = "%s: Can't open temporary file (%s)" fullword ascii
      $s7 = " command specific modifiers:" fullword ascii
      $s8 = "  --record-libdeps=<text> - specify the dependencies of this library" fullword ascii
      $s9 = "  [l <text> ]  - specify the dependencies of this library" fullword ascii
      $s10 = " commands:" fullword ascii
      $s11 = "       %s -M [<mri-script]" fullword ascii
      $s12 = "  --plugin <p> - load the specified plugin" fullword ascii
      $s13 = "  [u]          - only replace files that are newer than current archive contents" fullword ascii
      $s14 = "  r[ab][f][u]  - replace existing or insert new file(s) into the archive" fullword ascii
      $s15 = "  t[O][v]      - display contents of the archive" fullword ascii
      $s16 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/binutils-x86-64-linux-gnu.debug" fullword ascii
      $s17 = "  @<file>      - read options from <file>" fullword ascii
      $s18 = "  [V]          - display the version number" fullword ascii
      $s19 = "  -v --version                 Print version information" fullword ascii
      $s20 = "<https://sourceware.org/bugzilla/>" fullword ascii
      $s21 = "illegal output pathname for archive member: %s, using '%s' instead" fullword ascii
      $s22 = "%s: error: @-file refers to a directory" fullword ascii
      $s23 = "bfd_get_error" fullword ascii
      $s24 = "libbfd-2.40-system.so" fullword ascii
      $s25 = "  -h --help                    Print this help message" fullword ascii
      $s26 = "  [D]          - use zero for timestamps and uids/gids (default)" fullword ascii
      $s27 = "fatal error: libbfd ABI mismatch" fullword ascii
      $s28 = "  [N]          - use instance [count] of name" fullword ascii
      $s29 = "  [O]          - display offsets of files in the archive" fullword ascii
      $s30 = "  [s]          - create an archive index (cf. ranlib)" fullword ascii
      $s31 = "  [o]          - preserve original dates" fullword ascii
      $s32 = "  [c]          - do not warn if the library had to be created" fullword ascii
      $s33 = "  [b]          - put file(s) before [member-name] (same as [i])" fullword ascii
      $s34 = "  d            - delete file(s) from the archive" fullword ascii
      $s35 = "Warning: '%s' is a directory" fullword ascii
      $s36 = "  m[ab]        - move file(s) in the archive" fullword ascii
      $s37 = "  [a]          - put file(s) after [member-name]" fullword ascii
      $s38 = "bfd_make_readable" fullword ascii
      $s39 = "  [v]          - be verbose" fullword ascii
      $s40 = "  [S]          - do not build a symbol table" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_tic {
   strings:
      $s1 = "  -Q[n]      dump compiled description" fullword ascii
      $s2 = "# WARNING: this entry, %d bytes long, may core-dump %s libraries!" fullword ascii
      $s3 = "  -U         suppress post-processing of entries" fullword ascii
      $s4 = "%s=!!! %s WILL NOT CONVERT !!!" fullword ascii
      $s5 = "copy_input (target)" fullword ascii
      $s6 = "  -f         format complex strings for readability" fullword ascii
      $s7 = "%s: width = %d, tversion = %d, outform = %d" fullword ascii
      $s8 = "get_fkey_list" fullword ascii
      $s9 = "  -q    brief listing, removes headers" fullword ascii
      $s10 = "  -T         remove size-restrictions on compiled description" fullword ascii
      $s11 = "%s: Too many file names.  Usage:" fullword ascii
      $s12 = "%s: File name needed.  Usage:" fullword ascii
      $s13 = "# (%s removed to fit entry within %d bytes)" fullword ascii
      $s14 = "  -e<names>  translate/compile only entries named by comma-separated list" fullword ascii
      $s15 = "# (acsc removed to fit entry within %d bytes)" fullword ascii
      $s16 = "# (sgr removed to fit entry within %d bytes)" fullword ascii
      $s17 = "tic-conversion of %s failed" fullword ascii
      $s18 = "tic-expansion of %s failed" fullword ascii
      $s19 = "enter_superscript_mode but no exit_superscript_mode" fullword ascii
      $s20 = "exit_superscript_mode but no enter_superscript_mode" fullword ascii
      $s21 = "# (some function-key capabilities suppressed to fit entry within %d bytes)" fullword ascii
      $s22 = "tparm-conversion of %s(%d) differs between" fullword ascii
      $s23 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/ncurses-bin.debug" fullword ascii
      $s24 = "vt100 keypad map incomplete:%s" fullword ascii
      $s25 = "enter_subscript_mode but no exit_subscript_mode" fullword ascii
      $s26 = "function-key %s has delay" fullword ascii
      $s27 = "tparam error in sgr(%d): %s" fullword ascii
      $s28 = "syntax error in %s delay '%.*s'" fullword ascii
      $s29 = "exit_subscript_mode but no enter_subscript_mode" fullword ascii
      $s30 = "tic-conversion of %s changed value" fullword ascii
      $s31 = "  -c         check only, validate input without compiling or translating" fullword ascii
      $s32 = "%s: %s (no permission)" fullword ascii
      $s33 = "%s: %s entry is %d bytes long" fullword ascii
      $s34 = "tparm analyzed %d parameters for %s, expected %d" fullword ascii
      $s35 = "%s: value for %s is too long" fullword ascii
      $s36 = "expected %s to be %s, but actually %s" fullword ascii
      $s37 = "%s: resolved %s entry is %d bytes long" fullword ascii
      $s38 = "inconsistent suffix for %s, expected %c, have %c" fullword ascii
      $s39 = "tparm will use %d parameters for %s, expected %d" fullword ascii
      $s40 = "%s: %s is not a text-file" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule false_negative_bins_sg {
   strings:
      $s1 = "configuration error - unknown item '%s' (notify administrator)" fullword ascii
      $s2 = "user '%s' (login '%s' on %s) switched to group '%s'" fullword ascii
      $s3 = "Failed to crypt password with previous salt of group '%s'" fullword ascii
      $s4 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/login.debug" fullword ascii
      $s5 = "user '%s' (login '%s' on %s) returned to group '%lu'" fullword ascii
      $s6 = "user '%s' (login '%s' on %s) returned to group '%s'" fullword ascii
      $s7 = "%s: failed to crypt password with previous salt: %s" fullword ascii
      $s8 = "configuration error - cannot parse %s value: '%s'" fullword ascii
      $s9 = "Usage: sg group [[-c] command]" fullword ascii
      $s10 = "/etc/login.defs" fullword ascii
      $s11 = "LOGIN_STRING" fullword ascii
      $s12 = "LOGIN_KEEP_USERNAME" fullword ascii
      $s13 = "HUSHLOGIN_FILE" fullword ascii
      $s14 = "NOLOGINS_FILE" fullword ascii
      $s15 = "LOGIN_PLAIN_PROMPT" fullword ascii
      $s16 = "LOGIN_RETRIES" fullword ascii
      $s17 = "Invalid password for group '%s' from '%s'" fullword ascii
      $s18 = "cannot open login definitions %s [%s]" fullword ascii
      $s19 = "FAKE_SHELL" fullword ascii
      $s20 = "cannot read login definitions %s [%s]" fullword ascii
      $s21 = "sgetsgent" fullword ascii
      $s22 = "fgetsgent" fullword ascii
      $s23 = "getsgnam" fullword ascii
      $s24 = "xgetgrnam" fullword ascii
      $s25 = "xgetpwuid" fullword ascii
      $s26 = "xgetpwnam" fullword ascii
      $s27 = "xgetspnam" fullword ascii
      $s28 = "xgetgrgid" fullword ascii
      $s29 = "LOG_UNKFAIL_ENAB" fullword ascii
      $s30 = "FAILLOG_ENAB" fullword ascii
      $s31 = "LOG_OK_LOGINS" fullword ascii
      $s32 = "audit_log_user_message" fullword ascii
      $s33 = "USERDEL_CMD" fullword ascii
      $s34 = "unknown configuration item `%s'" fullword ascii
      $s35 = "unknown GID '%lu' used by user '%s'" fullword ascii
      $s36 = "crypt method not supported by libcrypt? (%s)" fullword ascii
      $s37 = "Cannot execute %s" fullword ascii
      $s38 = "%s: group '%s' does not exist" fullword ascii
      $s39 = "%s: failure forking: %s" fullword ascii
      $s40 = "SYSLOG_SU_ENAB" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_wc {
   strings:
      $s1 = "failed to get cpuid" fullword ascii
      $s2 = "?A NULL argv[0] was passed through an exec system call." fullword ascii
      $s3 = "                           If F is - then read names from standard input" fullword ascii
      $s4 = "  -L, --max-line-length  print the maximum display width" fullword ascii
      $s5 = "avx2 support not detected" fullword ascii
      $s6 = "using avx2 hardware support" fullword ascii
      $s7 = "  or:  %s [OPTION]... --files0-from=F" fullword ascii
      $s8 = "      --files0-from=F    read input from the files specified by" fullword ascii
      $s9 = "more than one FILE is specified.  A word is a non-zero-length sequence of" fullword ascii
      $s10 = "printable characters delimited by white space." fullword ascii
      $s11 = "_obstack_allocated_p" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "the following order: newline, word, character, byte, maximum line length." fullword ascii /* Goodware String - occured 1 times */
      $s13 = "The options below may be used to select which counts are printed, always in" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "_obstack_begin_1" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "obstack_alloc_failed_handler" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "_obstack_memory_used" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "  -l, --lines            print the newline counts" fullword ascii
      $s18 = "  -c, --bytes            print the byte counts" fullword ascii
      $s19 = "  -m, --chars            print the character counts" fullword ascii
      $s20 = "  -w, --words            print the word counts" fullword ascii
      $s21 = "max-line-length" fullword ascii /* Goodware String - occured 2 times */
      $s22 = "c9a936f1365db6cabbfc5c25c5d8c93af784ed.debug" fullword ascii
      $s23 = "Print newline, word, and byte counts for each FILE, and a total line if" fullword ascii /* Goodware String - occured 2 times */
      $s24 = "!\"unexpected error code from argv_iter\"" fullword ascii /* Goodware String - occured 2 times */
      $s25 = "%s:%lu: %s" fullword ascii /* Goodware String - occured 3 times */
      $s26 = "file operands cannot be combined with --files0-from" fullword ascii /* Goodware String - occured 3 times */
      $s27 = "when reading file names from stdin, no file name of %s allowed" fullword ascii /* Goodware String - occured 3 times */
      $s28 = "cannot read file names from %s" fullword ascii /* Goodware String - occured 3 times */
      $s29 = "invalid zero-length file name" fullword ascii /* Goodware String - occured 3 times */
      $s30 = "L9&s,H" fullword ascii
      $s31 = "t?H9E8u" fullword ascii
      $s32 = "src/wc.c" fullword ascii
      $s33 = "files0-from" fullword ascii /* Goodware String - occured 4 times */
      $s34 = "_obstack_free" fullword ascii /* Goodware String - occured 4 times */
      $s35 = "c9a936f1365db6cabbfc5c25c5d8c93af784ed" ascii
      $s36 = "__memmove_chk" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_ld {
   strings:
      $s1 = "%s: IFUNC symbol '%s' referenced in '%s' is defined in the executable and creates an unsatisfiable circular dependency." fullword ascii
      $s2 = "glibc.pthread.mutex_spin_count" fullword ascii
      $s3 = "relocation processing: %s%s" fullword ascii
      $s4 = "glibc.cpu.x86_non_temporal_threshold" fullword ascii
      $s5 = "display symbol table processing" fullword ascii
      $s6 = "EHWPOISON" fullword ascii
      $s7 = "Inconsistency detected by ld.so: %s: %u: %s%sAssertion `%s' failed!" fullword ascii
      $s8 = "Inconsistency detected by ld.so: %s: %u: %s%sUnexpected error: %s." fullword ascii
      $s9 = "failed to allocate memory to process tunables" fullword ascii
      $s10 = "  total startup time in dynamic loader: %s cycles" fullword ascii
      $s11 = "%s: cannot execute %s: %s" fullword ascii
      $s12 = "%s: cannot execute %s: %d" fullword ascii
      $s13 = "ELF load command address/offset not page-aligned" fullword ascii
      $s14 = "setting environment variables (which would be inherited by subprocesses)." fullword ascii
      $s15 = "__rtld_mutex_init" fullword ascii
      $s16 = "Usage: %s [OPTION]... EXECUTABLE-FILE [ARGS-FOR-PROGRAM...]" fullword ascii
      $s17 = "EKEYEXPIRED" fullword ascii
      $s18 = "target_seg_index1 == 0" fullword ascii
      $s19 = "invalid target namespace in dlmopen()" fullword ascii
      $s20 = "instead of the program interpreter specified in the executable file you" fullword ascii
      $s21 = "path.system_dirs[0x%x]=" fullword ascii
      $s22 = "%s: %s cycles (%s%%)" fullword ascii
      $s23 = "unsupported version %s of Verdef record" fullword ascii
      $s24 = "unsupported version %s of Verneed record" fullword ascii
      $s25 = "TLS generation counter wrapped!  Please report as described in <http://www.debian.org/Bugs/>." fullword ascii
      $s26 = "DYNAMIC LINKER BUG!!!" fullword ascii
      $s27 = "display relocation processing" fullword ascii
      $s28 = "ERROR: audit interface '%s' requires version %d (maximum supported version %d); ignored." fullword ascii
      $s29 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii
      $s30 = "symbol=%s;  lookup in file=%s [%lu]" fullword ascii
      $s31 = "%s: error: %s: %s (%s)" fullword ascii
      $s32 = "type != ET_EXEC || l->l_type == lt_executable" fullword ascii
      $s33 = "(bitmask_nwords & (bitmask_nwords - 1)) == 0" fullword ascii
      $s34 = "symbol lookup error" fullword ascii
      $s35 = "failed to map segment from shared object" fullword ascii
      $s36 = "glibc.malloc.hugetlb" fullword ascii
      $s37 = "error while loading shared libraries" fullword ascii
      $s38 = "version lookup error" fullword ascii
      $s39 = "type == lt_executable" fullword ascii
      $s40 = "You may invoke the program interpreter program directly from the command" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      8 of them
}

rule false_negative_bins_gzip {
   strings:
      $s1 = "%s: %s: header checksum 0x%04x != computed checksum 0x%04x" fullword ascii
      $s2 = "%s: %s has %lu other link%s -- file ignored" fullword ascii
      $s3 = "invalid compressed data -- Huffman code bit length out of range" fullword ascii
      $s4 = "invalid compressed data -- unexpected end of file" fullword ascii
      $s5 = "%s: option --ascii ignored on this system" fullword ascii
      $s6 = "the GNU General Public License <https://www.gnu.org/licenses/gpl.html>." fullword ascii
      $s7 = " -- %s %s" fullword ascii
      $s8 = "  -d, --decompress  decompress" fullword ascii
      $s9 = "  -l, --list        list compressed file contents" fullword ascii
      $s10 = "  -S, --suffix=SUF  use suffix SUF on compressed files" fullword ascii
      $s11 = "%s: invalid suffix '%s'" fullword ascii
      $s12 = "%s: %s: file size changed while zipping" fullword ascii
      $s13 = "%s: %s: non-option in GZIP environment variable" fullword ascii
      $s14 = "%s: %s: MTIME %lu out of range for this platform" fullword ascii
      $s15 = "%s: warning: GZIP environment variable is deprecated; use an alias or script" fullword ascii
      $s16 = "  -r, --recursive   operate recursively on directories" fullword ascii
      $s17 = "%s: timestamp restored" fullword ascii
      $s18 = "--%s: " fullword ascii
      $s19 = "  -f, --force       force overwrite of output file and compress links" fullword ascii
      $s20 = "  -V, --version     display version number" fullword ascii
      $s21 = "  -1, --fast        compress faster" fullword ascii
      $s22 = "replaced with" fullword ascii
      $s23 = "  -9, --best        compress better" fullword ascii
      $s24 = "      --synchronous synchronous output (safer if system crashes, but slower)" fullword ascii
      $s25 = "  -t, --test        test compressed file integrity" fullword ascii
      $s26 = "rsyncable" fullword ascii /* Goodware String - occured 1 times */
      $s27 = " (totals)" fullword ascii
      $s28 = "ab:cdfhH?klLmMnNqrS:tvVZ123456789" fullword ascii
      $s29 = "Y@file timestamp out of range for gzip format" fullword ascii
      $s30 = "option not valid in GZIP environment variable" fullword ascii
      $s31 = "D$XHcD$(L" fullword ascii
      $s32 = "6AUATUSB" fullword ascii
      $s33 = "Copyright (C) 2018 Free Software Foundation, Inc." fullword ascii
      $s34 = "-presume-input-tty" fullword ascii /* Goodware String - occured 1 times */
      $s35 = "too few leaves in Huffman tree" fullword ascii
      $s36 = " do you wish to overwrite (y or n)? " fullword ascii
      $s37 = "c767c02e183bb92c91cd56be96c493d8255f86.debug" fullword ascii
      $s38 = "%s: %s has the sticky bit set - file ignored" fullword ascii /* Goodware String - occured 2 times */
      $s39 = "Written by Jean-loup Gailly." fullword ascii /* Goodware String - occured 2 times */
      $s40 = "name too short" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule false_negative_bins_nm {
   strings:
      $s1 = "  -C, --demangle[=STYLE] Decode mangled/processed symbol names" fullword ascii
      $s2 = "bfd_set_default_target" fullword ascii
      $s3 = "bfd_target_list" fullword ascii
      $s4 = "      --target=BFDNAME   Specify the target object format as BFDNAME" fullword ascii
      $s5 = "                         Specify how to treat UTF-8 encoded unicode characters" fullword ascii
      $s6 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/binutils-x86-64-linux-gnu.debug" fullword ascii
      $s7 = "<https://sourceware.org/bugzilla/>" fullword ascii
      $s8 = "%s: error: @-file refers to a directory" fullword ascii
      $s9 = "bfd_get_error" fullword ascii
      $s10 = "bfd_get_arch_size" fullword ascii
      $s11 = "bfd_get_next_mapent" fullword ascii
      $s12 = "bfd_get_reloc_upper_bound" fullword ascii
      $s13 = "  -A, --print-file-name  Print name of the input file before every symbol" fullword ascii
      $s14 = "invalid argument to -U/--unicode: %s" fullword ascii
      $s15 = "libbfd-2.40-system.so" fullword ascii
      $s16 = "fatal error: libbfd ABI mismatch" fullword ascii
      $s17 = "Warning: '%s' is a directory" fullword ascii
      $s18 = "(GNU Binutils for Debian) 2.40" fullword ascii
      $s19 = "bfd_set_error_program_name" fullword ascii
      $s20 = "with-symbol-versions" fullword ascii
      $s21 = "without-symbol-versions" fullword ascii
      $s22 = "  -o                     Same as -A" fullword ascii
      $s23 = "<unknown>: %d/%d" fullword ascii
      $s24 = "  -e                     (ignored)" fullword ascii
      $s25 = " List symbols in [file(s)] (a.out by default)." fullword ascii
      $s26 = "%s: plugin needed to handle lto object" fullword ascii
      $s27 = "  -P, --portability      Same as --format=posix" fullword ascii
      $s28 = "      --with-symbol-versions  Display version strings after symbol names" fullword ascii
      $s29 = "  -V, --version          Display this program's version number" fullword ascii
      $s30 = "cause of error unknown" fullword ascii
      $s31 = "default" fullword ascii /* Goodware String - occured 709 times */
      $s32 = "target" fullword ascii /* Goodware String - occured 880 times */
      $s33 = "bfd_plugin_set_program_name" fullword ascii
      $s34 = " The options are:" fullword ascii
      $s35 = "bfd_plugin_set_plugin" fullword ascii
      $s36 = "Copyright (C) 2023 Free Software Foundation, Inc." fullword ascii
      $s37 = "bfd_check_format" fullword ascii
      $s38 = "bfd_openr_next_archived_file" fullword ascii
      $s39 = "x86_64-pc-linux-gnu" fullword ascii
      $s40 = "bfd_check_format_matches" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_strings {
   strings:
      $s1 = "  -T --target=<BFDNAME>     Specify the binary file format" fullword ascii
      $s2 = "%s: Reading section %s failed: %s" fullword ascii
      $s3 = "  -U {d|s|i|x|e|h}          Specify how to treat UTF-8 encoded unicode characters" fullword ascii
      $s4 = "bfd_set_default_target" fullword ascii
      $s5 = "bfd_target_list" fullword ascii
      $s6 = "  -a - --all                Scan the entire file, not just the data section [default]" fullword ascii
      $s7 = "  -e --encoding={s,S,b,l,B,L} Select character size and endianness:" fullword ascii
      $s8 = "  -w --include-all-whitespace Include all whitespace as valid string characters" fullword ascii
      $s9 = "  -s --output-separator=<string> String used to separate strings in output." fullword ascii
      $s10 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/binutils-x86-64-linux-gnu.debug" fullword ascii
      $s11 = "<https://sourceware.org/bugzilla/>" fullword ascii
      $s12 = "  -v -V --version           Print the program's version number" fullword ascii
      $s13 = "%s: error: @-file refers to a directory" fullword ascii
      $s14 = "bfd_get_error" fullword ascii
      $s15 = "bfd_malloc_and_get_section" fullword ascii
      $s16 = "invalid argument to -U/--unicode: %s" fullword ascii
      $s17 = "  -d --data                 Only scan the data sections in the file" fullword ascii
      $s18 = "libbfd-2.40-system.so" fullword ascii
      $s19 = "fatal error: libbfd ABI mismatch" fullword ascii
      $s20 = "Warning: '%s' is a directory" fullword ascii
      $s21 = "(GNU Binutils for Debian) 2.40" fullword ascii
      $s22 = "bfd_set_error_program_name" fullword ascii
      $s23 = " Display printable strings in [file(s)] (stdin by default)" fullword ascii
      $s24 = "  -o                        An alias for --radix=o" fullword ascii
      $s25 = "  -f --print-file-name      Print the name of the file before each string" fullword ascii
      $s26 = "  -h --help                 Display this information" fullword ascii
      $s27 = "cause of error unknown" fullword ascii
      $s28 = "encoding" fullword ascii /* Goodware String - occured 628 times */
      $s29 = "default" fullword ascii /* Goodware String - occured 709 times */
      $s30 = "target" fullword ascii /* Goodware String - occured 880 times */
      $s31 = " The options are:" fullword ascii
      $s32 = "Copyright (C) 2023 Free Software Foundation, Inc." fullword ascii
      $s33 = "bfd_check_format" fullword ascii
      $s34 = "x86_64-pc-linux-gnu" fullword ascii
      $s35 = "adfhHn:wot:e:T:s:U:Vv0123456789" fullword ascii
      $s36 = "  --unicode={default|show|invalid|hex|escape|highlight}" fullword ascii
      $s37 = "include-all-whitespace" fullword ascii
      $s38 = "ICE: unexpected unicode display type" fullword ascii
      $s39 = "output-separator" fullword ascii
      $s40 = "ICE: bad arguments to print_unicode_buffer" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      8 of them
}

rule run_parts {
   strings:
      $s1 = "failed to exec %s: %s" fullword ascii
      $s2 = "      --new-session   run each script in a separate process session" fullword ascii
      $s3 = "run-parts: component %s is not an executable plain file" fullword ascii
      $s4 = "run-parts: failed to rewind temporary file: %s" fullword ascii
      $s5 = "run-parts: failed to write to temporary file" fullword ascii
      $s6 = "  -a, --arg=ARGUMENT  pass ARGUMENT to scripts, use once for each argument." fullword ascii
      $s7 = "failed to read from error pipe: %s" fullword ascii
      $s8 = "failed to read from stdout pipe: %s" fullword ascii
      $s9 = "      --stdin         multiplex stdin to scripts being run, using temporary file" fullword ascii
      $s10 = "failed to stat component %s: %s" fullword ascii
      $s11 = "run-parts: failed to copy content of stdin" fullword ascii
      $s12 = "      --reverse       reverse execution order of scripts." fullword ascii
      $s13 = "run-parts: component %s is a broken symbolic link" fullword ascii
      $s14 = "failed to open directory %s: %s" fullword ascii
      $s15 = "      --exit-on-error exit as soon as a script returns with a non-zero exit" fullword ascii
      $s16 = "run-parts: executing %s" fullword ascii
      $s17 = "      --report        print script names if they produce output." fullword ascii
      $s18 = "Try `run-parts --help' for more information." fullword ascii
      $s19 = "\"%s\": hierre pass, excsre %s" fullword ascii
      $s20 = "This is free software; see the GNU General Public License version 2" fullword ascii
      $s21 = "Debian run-parts program, version 5.7" fullword ascii
      $s22 = "run-parts: failed to read from stdin" fullword ascii
      $s23 = "      --test          print script names which would run, but don't run them." fullword ascii
      $s24 = "--list and --test can not be used together" fullword ascii
      $s25 = "  -d, --debug         print script names while checking them." fullword ascii
      $s26 = "  -v, --verbose       print script names before running them." fullword ascii
      $s27 = "lsbsysinit" fullword ascii
      $s28 = "run-parts: " fullword ascii
      $s29 = "exit-on-error" fullword ascii
      $s30 = "\"%s\": customre %s" fullword ascii
      $s31 = "Usage: run-parts [OPTION]... DIRECTORY" fullword ascii
      $s32 = "^[a-z0-9-].*\\.dpkg-(old|dist|new|tmp)$" fullword ascii
      $s33 = "\"%s\": tradre %s" fullword ascii
      $s34 = "new-session" fullword ascii
      $s35 = "Copyright (C) 1994 Ian Jackson, Copyright (C) 1996 Jeff Noxon." fullword ascii
      $s36 = "bad umask value" fullword ascii
      $s37 = "  -V, --version       output version information and exit." fullword ascii
      $s38 = "reverse" fullword ascii /* Goodware String - occured 198 times */
      $s39 = "__fdelt_chk" fullword ascii
      $s40 = "GLIBC_2.15" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      8 of them
}

rule false_negative_bins_cut {
   strings:
      $s1 = "byte/character offset %s is too large" fullword ascii
      $s2 = "                            the -s option is specified" fullword ascii
      $s3 = "  -n                      (ignored)" fullword ascii
      $s4 = "2badf9c70583dc86ccf38d135e9cf1fbb9daaa.debug" fullword ascii
      $s5 = "invalid field range" fullword ascii
      $s6 = "      --complement        complement the set of selected bytes, characters" fullword ascii
      $s7 = "only one list may be specified" fullword ascii
      $s8 = "invalid byte or character range" fullword ascii
      $s9 = "W(H;W0" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "invalid byte/character position %s" fullword ascii
      $s11 = "byte/character positions are numbered from 1" fullword ascii
      $s12 = "invalid field value %s" fullword ascii
      $s13 = "invalid decreasing range" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "2badf9c70583dc86ccf38d135e9cf1fbb9daaa" ascii
      $s15 = "invalid range with no endpoint: -" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "fields are numbered from 1" fullword ascii
      $s17 = "missing list of byte/character positions" fullword ascii
      $s18 = "Usage: %s OPTION... [FILE]..." fullword ascii /* Goodware String - occured 1 times */
      $s19 = "cut_fields" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "only-delimited" fullword ascii /* Goodware String - occured 2 times */
      $s21 = "      --output-delimiter=STRING  use STRING as the output delimiter" fullword ascii
      $s22 = "  -b, --bytes=LIST        select only these bytes" fullword ascii
      $s23 = "an input delimiter may be specified only when operating on fields" fullword ascii /* Goodware String - occured 2 times */
      $s24 = "Each range is one of:" fullword ascii /* Goodware String - occured 2 times */
      $s25 = "only when operating on fields" fullword ascii /* Goodware String - occured 2 times */
      $s26 = "  -s, --only-delimited    do not print lines not containing delimiters" fullword ascii
      $s27 = "field number %s is too large" fullword ascii /* Goodware String - occured 2 times */
      $s28 = "  -d, --delimiter=DELIM   use DELIM instead of TAB for field delimiter" fullword ascii
      $s29 = "the delimiter must be a single character" fullword ascii /* Goodware String - occured 2 times */
      $s30 = "  -z, --zero-terminated    line delimiter is NUL, not newline" fullword ascii
      $s31 = "Use one, and only one of -b, -c or -f.  Each LIST is made up of one" fullword ascii /* Goodware String - occured 2 times */
      $s32 = "missing list of fields" fullword ascii /* Goodware String - occured 2 times */
      $s33 = "you must specify a list of bytes, characters, or fields" fullword ascii /* Goodware String - occured 2 times */
      $s34 = "range, or many ranges separated by commas.  Selected input is written" fullword ascii /* Goodware String - occured 2 times */
      $s35 = "Print selected parts of lines from each FILE to standard output." fullword ascii /* Goodware String - occured 2 times */
      $s36 = "  -M    from first to M'th (included) byte, character or field" fullword ascii
      $s37 = "suppressing non-delimited lines makes sense" fullword ascii /* Goodware String - occured 2 times */
      $s38 = "  N-    from N'th byte, character or field, to end of line" fullword ascii
      $s39 = "in the same order that it is read, and is written exactly once." fullword ascii /* Goodware String - occured 2 times */
      $s40 = "  -f, --fields=LIST       select only these fields;  also print any line" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_uniq {
   strings:
      $s1 = "grouping and printing repeat counts is meaningless" fullword ascii
      $s2 = "--group is mutually exclusive with -c/-d/-D/-u" fullword ascii
      $s3 = "You may want to sort the input first, or use 'sort -u' without 'uniq'." fullword ascii
      $s4 = "  -f, --skip-fields=N   avoid comparing the first N fields" fullword ascii
      $s5 = "  -w, --check-chars=N   compare no more than N characters in lines" fullword ascii
      $s6 = "  -s, --skip-chars=N    avoid comparing the first N characters" fullword ascii
      $s7 = "writing to OUTPUT (or standard output)." fullword ascii /* Goodware String - occured 1 times */
      $s8 = "-0123456789Dcdf:is:uw:z" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "characters.  Fields are skipped before chars." fullword ascii /* Goodware String - occured 1 times */
      $s10 = "Filter adjacent matching lines from INPUT (or standard input)," fullword ascii /* Goodware String - occured 1 times */
      $s11 = "With no options, matching lines are merged to the first occurrence." fullword ascii /* Goodware String - occured 1 times */
      $s12 = "d8362f8df5042d3e7144ee530c4fa9e0216263.debug" fullword ascii
      $s13 = "Note: 'uniq' does not detect repeated lines unless they are adjacent." fullword ascii /* Goodware String - occured 1 times */
      $s14 = "A field is a run of blanks (usually spaces and/or TABs), then non-blank" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "  -z, --zero-terminated     line delimiter is NUL, not newline" fullword ascii
      $s16 = "invalid number of bytes to compare" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "      --group[=METHOD]  show all items, separating groups with an empty line;" fullword ascii
      $s18 = "skip-chars" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "  -u, --unique          only print unique lines" fullword ascii
      $s20 = "      --all-repeated[=METHOD]  like -D, but allow separating groups" fullword ascii
      $s21 = "printing all duplicated lines and repeat counts is meaningless" fullword ascii /* Goodware String - occured 2 times */
      $s22 = "--all-repeated" fullword ascii /* Goodware String - occured 2 times */
      $s23 = "  -c, --count           prefix lines by the number of occurrences" fullword ascii
      $s24 = "check-chars" fullword ascii /* Goodware String - occured 2 times */
      $s25 = "invalid number of bytes to skip" fullword ascii /* Goodware String - occured 2 times */
      $s26 = "invalid number of fields to skip" fullword ascii /* Goodware String - occured 2 times */
      $s27 = "Usage: %s [OPTION]... [INPUT [OUTPUT]]" fullword ascii /* Goodware String - occured 2 times */
      $s28 = "skip-fields" fullword ascii /* Goodware String - occured 2 times */
      $s29 = "  -i, --ignore-case     ignore differences in case when comparing" fullword ascii
      $s30 = "D$+A8G" fullword ascii
      $s31 = "0123456789Dcdf" ascii
      $s32 = "--group" fullword ascii
      $s33 = "d8362f8df5042d3e7144ee530c4fa9e0216263" ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_comm {
   strings:
      $s1 = "When FILE1 or FILE2 (not both) is -, read standard input." fullword ascii
      $s2 = "  %s -3 file1 file2  Print lines in file1 not in file2, and vice versa." fullword ascii
      $s3 = "  %s -12 file1 file2  Print only lines present in both file1 and file2." fullword ascii
      $s4 = "Note, comparisons honor the rules specified by 'LC_COLLATE'." fullword ascii
      $s5 = "d096699f4027e3001c6e5c48d962fdfd1c470a.debug" fullword ascii
      $s6 = "input is not in sorted order" fullword ascii
      $s7 = "multiple output delimiters specified" fullword ascii
      $s8 = "AWAVAUATU1" fullword ascii
      $s9 = "%s%s%s%s%s%s%s%c" fullword ascii
      $s10 = "file %d is not in sorted order" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "1c6e5c48d962fdfd1c470a" ascii
      $s12 = "d096699f4027e3001c6e5c48d962fdfd1c470a" ascii
      $s13 = "nocheck-order" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "      --total             output a summary" fullword ascii
      $s15 = "      --nocheck-order     do not check that the input is correctly sorted" fullword ascii
      $s16 = "  -3                      suppress column 3 (lines that appear in both files)" fullword ascii
      $s17 = "      --output-delimiter=STR  separate columns with STR" fullword ascii
      $s18 = "and column three contains lines common to both files." fullword ascii /* Goodware String - occured 2 times */
      $s19 = "With no options, produce three-column output.  Column one contains" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "      --check-order       check that the input is correctly sorted, even" fullword ascii
      $s21 = "  -1                      suppress column 1 (lines unique to FILE1)" fullword ascii
      $s22 = "lines unique to FILE1, column two contains lines unique to FILE2," fullword ascii /* Goodware String - occured 2 times */
      $s23 = "  -z, --zero-terminated   line delimiter is NUL, not newline" fullword ascii
      $s24 = "Compare sorted files FILE1 and FILE2 line by line." fullword ascii /* Goodware String - occured 2 times */
      $s25 = "  -2                      suppress column 2 (lines unique to FILE2)" fullword ascii
      $s26 = "output-delimiter" fullword ascii /* Goodware String - occured 3 times */
      $s27 = "D$+A8G" fullword ascii
      $s28 = "                            if all input lines are pairable" fullword ascii
      $s29 = "d096699f4027e3" ascii
      $s30 = "t$@HcD$L1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_chmod {
   strings:
      $s1 = "      --preserve-root    fail to operate recursively on '/'" fullword ascii
      $s2 = "  -v, --verbose          output a diagnostic for every file processed" fullword ascii
      $s3 = "  -f, --silent, --quiet  suppress most error messages" fullword ascii
      $s4 = "      --no-preserve-root  do not treat '/' specially (the default)" fullword ascii
      $s5 = "  -c, --changes          like verbose but report only when a change is made" fullword ascii
      $s6 = "  or:  %s [OPTION]... --reference=RFILE FILE..." fullword ascii
      $s7 = "state->magic == 9827862" fullword ascii
      $s8 = "lib/cycle-check.c" fullword ascii
      $s9 = "cannot operate on dangling symlink %s" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "With --reference, change the mode of each FILE to that of RFILE." fullword ascii /* Goodware String - occured 1 times */
      $s11 = "877f12944e750c88a16480f4eb8fbb7a94c726.debug" fullword ascii
      $s12 = "mode of %s changed from %04lo (%s) to %04lo (%s)" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "Rcfvr::w::x::X::s::t::u::g::o::a::,::+::=::0::1::2::3::4::5::6::7::" fullword ascii
      $s14 = "failed to change mode of %s from %04lo (%s) to %04lo (%s)" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "Each MODE is of the form '[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=][0-7]+'." fullword ascii
      $s16 = "%s could not be accessed" fullword ascii
      $s17 = "      --reference=RFILE  use RFILE's mode instead of MODE values" fullword ascii
      $s18 = "  -R, --recursive        change files and directories recursively" fullword ascii
      $s19 = "%s: new permissions are %s, not %s" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "invalid mode: %s" fullword ascii /* Goodware String - occured 2 times */
      $s21 = "cannot combine mode and --reference options" fullword ascii /* Goodware String - occured 2 times */
      $s22 = "  or:  %s [OPTION]... OCTAL-MODE FILE..." fullword ascii
      $s23 = "changing permissions of %s" fullword ascii /* Goodware String - occured 3 times */
      $s24 = "mode of %s retained as %04lo (%s)" fullword ascii /* Goodware String - occured 3 times */
      $s25 = "getting new attributes of %s" fullword ascii /* Goodware String - occured 3 times */
      $s26 = "Usage: %s [OPTION]... MODE[,MODE]... FILE..." fullword ascii /* Goodware String - occured 3 times */
      $s27 = "L$8H9u0tFM" fullword ascii
      $s28 = "I9T$8s/H" fullword ascii
      $s29 = "lib/xfts.c" fullword ascii
      $s30 = "H=OAFSt" fullword ascii
      $s31 = "fchmodat" fullword ascii /* Goodware String - occured 4 times */
      $s32 = "Change the mode of each FILE to MODE." fullword ascii /* Goodware String - occured 4 times */
      $s33 = "877f12944e750c88a16480f4eb8fbb7a94c726" ascii
      $s34 = "L;D$Hs;H" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_tail {
   strings:
      $s1 = "  -f, --follow[={name|descriptor}]" fullword ascii
      $s2 = "                             with inotify and --pid=P, check process P at" fullword ascii
      $s3 = "      --pid=PID            with -f, terminate after process ID, PID dies" fullword ascii
      $s4 = "error reading inotify event" fullword ascii
      $s5 = "error waiting for inotify and output events" fullword ascii
      $s6 = "  -n, --lines=[+]NUM       output the last NUM lines, instead of the last %d;" fullword ascii
      $s7 = "  -q, --quiet, --silent    never output headers giving file names" fullword ascii
      $s8 = "warning: --retry only effective for the initial open" fullword ascii
      $s9 = "  -v, --verbose            always output headers giving file names" fullword ascii
      $s10 = "warning: --retry ignored; --retry is useful only when following" fullword ascii
      $s11 = "%s has been replaced with an untailable remote file" fullword ascii
      $s12 = "newlocale" fullword ascii
      $s13 = "                             or use -n +NUM to output starting with line NUM" fullword ascii
      $s14 = "  -c, --bytes=[+]NUM       output the last NUM bytes; or use -c +NUM to" fullword ascii
      $s15 = "invalid maximum number of unchanged stats between opens" fullword ascii
      $s16 = "directory containing watched file was removed" fullword ascii
      $s17 = "inotify resources exhausted" fullword ascii
      $s18 = "                             an absent option argument means 'descriptor'" fullword ascii
      $s19 = "NUM may have a multiplier suffix:" fullword ascii
      $s20 = "its end.  This default behavior is not desirable when you really want to" fullword ascii /* Goodware String - occured 1 times */
      $s21 = "inotify_add_watch" fullword ascii
      $s22 = "%s has been replaced with an untailable symbolic link" fullword ascii
      $s23 = "c3f841844926bb8253966b3de5807fae025930.debug" fullword ascii
      $s24 = "; giving up on this name" fullword ascii
      $s25 = "%s has appeared;  following new file" fullword ascii
      $s26 = "Ian Lance Taylor" fullword ascii /* Goodware String - occured 1 times */
      $s27 = "%s has been replaced with an untailable file%s" fullword ascii
      $s28 = "invalid number of seconds: %s" fullword ascii
      $s29 = "%s was replaced" fullword ascii
      $s30 = "inotify_rm_watch" fullword ascii
      $s31 = "strtod_l" fullword ascii
      $s32 = "-disable-inotify" fullword ascii /* Goodware String - occured 1 times */
      $s33 = "%s has been replaced;  following new file" fullword ascii
      $s34 = "Clib/xstrtol.c" fullword ascii
      $s35 = "named file in a way that accommodates renaming, removal and creation." fullword ascii /* Goodware String - occured 1 times */
      $s36 = "option used in invalid context -- %c" fullword ascii /* Goodware String - occured 1 times */
      $s37 = "inotify_init" fullword ascii
      $s38 = "fflush_unlocked" fullword ascii
      $s39 = "invalid PID" fullword ascii
      $s40 = "c:n:fFqs:vz0123456789" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_head {
   strings:
      $s1 = "  -n, --lines=[-]NUM       print the first NUM lines instead of the first %d;" fullword ascii
      $s2 = "  -v, --verbose            always print headers giving file names" fullword ascii
      $s3 = "  -q, --quiet, --silent    never print headers giving file names" fullword ascii
      $s4 = "failed to close %s" fullword ascii
      $s5 = "Print the first %d lines of each FILE to standard output." fullword ascii
      $s6 = "NUM may have a multiplier suffix:" fullword ascii
      $s7 = "invalid trailing option -- %c" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "6446c8f146b69e22df9ba842c278c30b6bc9d0.debug" fullword ascii
      $s9 = "  -z, --zero-terminated    line delimiter is NUL, not newline" fullword ascii
      $s10 = "%s: cannot seek to relative offset %s" fullword ascii /* Goodware String - occured 2 times */
      $s11 = "bkKmMGTPEZY0" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "-presume-input-pipe" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "Binary prefixes can be used, too: KiB=K, MiB=M, and so on." fullword ascii
      $s14 = "%s: file has shrunk too much" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "  -c, --bytes=[-]NUM       print the first NUM bytes of each file;" fullword ascii
      $s16 = "b 512, kB 1000, K 1024, MB 1000*1000, M 1024*1024," fullword ascii /* Goodware String - occured 3 times */
      $s17 = "With more than one FILE, precede each with a header giving the file name." fullword ascii /* Goodware String - occured 4 times */
      $s18 = "%s==> %s <==" fullword ascii /* Goodware String - occured 4 times */
      $s19 = "GB 1000*1000*1000, G 1024*1024*1024, and so on for T, P, E, Z, Y." fullword ascii /* Goodware String - occured 4 times */
      $s20 = "error writing %s" fullword ascii /* Goodware String - occured 4 times */
      $s21 = "invalid number of lines" fullword ascii /* Goodware String - occured 4 times */
      $s22 = "invalid number of bytes" fullword ascii /* Goodware String - occured 4 times */
      $s23 = "%s: cannot seek to offset %s" fullword ascii /* Goodware String - occured 4 times */
      $s24 = "L9l$XH" fullword ascii
      $s25 = "6446c8f146b69e22df9ba842c278c30b6bc9d0" ascii
      $s26 = "c:n:qvz0123456789" fullword ascii
      $s27 = "t$(L9$$s_H" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_date {
   strings:
      $s1 = "error: %s:%d" fullword ascii
      $s2 = "'@timespec' - always UTC" fullword ascii
      $s3 = "  -  (hyphen) do not pad the field" fullword ascii
      $s4 = "error: invalid hour %ld%s" fullword ascii
      $s5 = " isdst=%d%s" fullword ascii
      $s6 = "XXA NULL argv[0] was passed through an exec system call." fullword ascii
      $s7 = "  %:z  +hh:mm numeric time zone (e.g., -04:00)" fullword ascii
      $s8 = "  %::z  +hh:mm:ss numeric time zone (e.g., -04:00:00)" fullword ascii
      $s9 = "%Y-%m-%dT%H:%M:%S,%N%:z" fullword ascii
      $s10 = "%Y-%m-%dT%H:%M:%S%:z" fullword ascii
      $s11 = "error: tzalloc (\"%s\") failed" fullword ascii
      $s12 = "error: adding relative date resulted in an invalid date: '%s'" fullword ascii
      $s13 = "error: unknown word '%s'" fullword ascii
      $s14 = "error: parsing failed, stopped at '%s'" fullword ascii
      $s15 = "error: day '%s' (day ordinal=%ld number=%d) resulted in an invalid date: '%s'" fullword ascii
      $s16 = "system default" fullword ascii
      $s17 = "TZ=\"UTC0\" environment value or -u" fullword ascii
      $s18 = "  +  pad with zeros, and put '+' before future years with >4 digits" fullword ascii
      $s19 = "  $ date --date='@2147483647'" fullword ascii
      $s20 = "  %:::z  numeric time zone with : to necessary precision (e.g., -04, +05:30)" fullword ascii
      $s21 = "With -s, or with [MMDDhhmm[[CC]YY][.ss]], set the date and time." fullword ascii
      $s22 = "  -I[FMT], --iso-8601[=FMT]  output date/time in ISO 8601 format." fullword ascii
      $s23 = "%Y-%m-%dT%H%:z" fullword ascii
      $s24 = "%Y-%m-%dT%H:%M%:z" fullword ascii
      $s25 = "error: year, month, or day overflow" fullword ascii
      $s26 = "error: seen multiple time parts" fullword ascii
      $s27 = "error: seen multiple time-zone parts" fullword ascii
      $s28 = "using specified time as starting value: '%s'" fullword ascii
      $s29 = "warning: value %ld has %ld digits. Assuming YYYY/MM/DD" fullword ascii
      $s30 = "final: %s (UTC%s)" fullword ascii
      $s31 = "warning: when adding relative days, it is recommended to specify noon" fullword ascii
      $s32 = "new start date: '%s' is '%s'" fullword ascii
      $s33 = "%s (day ordinal=%ld number=%d)" fullword ascii
      $s34 = "error: parsing failed" fullword ascii
      $s35 = "error: seen multiple days parts" fullword ascii
      $s36 = "warning: day (%s) ignored when explicit dates are given" fullword ascii
      $s37 = "timezone: TZ=\"%s\" environment value" fullword ascii
      $s38 = "starting date/time: '%s'" fullword ascii
      $s39 = "final: %s (UTC)" fullword ascii
      $s40 = "warning: value %ld has less than 4 digits. Assuming MM/DD/YY[YY]" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule false_negative_bins_apt_get {
   strings:
      $s1 = "_Z10DoDownloadR11CommandLine" fullword ascii
      $s2 = "indextargets" fullword ascii
      $s3 = "_Z11DoChangelogR11CommandLine" fullword ascii
      $s4 = "_ZNK11IndexTarget6OptionB5cxx11ENS_10OptionKeysE" fullword ascii
      $s5 = "Usage: apt-get [options] command" fullword ascii
      $s6 = "_Z16ParseCommandLineR11CommandLine7APT_CMDPKP13ConfigurationPP9pkgSystemiPPKcPFbS0_EPFSt6vectorI19aptDispatchWithHelpSaISF_EEvE" fullword ascii
      $s7 = "Download and display the changelog for the given package" fullword ascii
      $s8 = "_ZNK11IndexTarget6FormatENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
      $s9 = "APT::Get::IndexTargets::ReleaseInfo" fullword ascii
      $s10 = "APT::Get::IndexTargets::Format" fullword ascii
      $s11 = "changelog" fullword ascii
      $s12 = "Download the binary package into the current directory" fullword ascii
      $s13 = "_Z7DoCleanR11CommandLine" fullword ascii
      $s14 = "_Z13DoDistUpgradeR11CommandLine" fullword ascii
      $s15 = "_Z10DoBuildDepR11CommandLine" fullword ascii
      $s16 = "_ZN11CommandLineC1Ev" fullword ascii
      $s17 = "_ZN11CommandLineD1Ev" fullword ascii
      $s18 = "_Z5DoMooR11CommandLine" fullword ascii
      $s19 = "_Z9DoUpgradeR11CommandLine" fullword ascii
      $s20 = "_Z19DispatchCommandLineR11CommandLineRKSt6vectorINS_8DispatchESaIS2_EE" fullword ascii
      $s21 = "_Z9DoInstallR11CommandLine" fullword ascii
      $s22 = "_Z11DoAutoCleanR11CommandLine" fullword ascii
      $s23 = "_Z8DoUpdateR11CommandLine" fullword ascii
      $s24 = "_Z8DoSourceR11CommandLine" fullword ascii
      $s25 = "_Z19CheckIfSimulateModeR11CommandLine" fullword ascii
      $s26 = "_ZNK11CommandLine8FileSizeEv" fullword ascii
      $s27 = "gIcSt11char_traitsIcESaIcEEERK11CommandLine" fullword ascii
      $s28 = "apt-get is a command line interface for retrieval of packages" fullword ascii
      $s29 = "_Z12_GetErrorObjv" fullword ascii
      $s30 = "Erase old downloaded archive files" fullword ascii
      $s31 = "_ZN19pkgVersioningSystem13GlobalListLenE" fullword ascii
      $s32 = "_ZN19pkgVersioningSystem10GlobalListE" fullword ascii
      $s33 = "Erase downloaded archive files" fullword ascii
      $s34 = "Download source archives" fullword ascii
      $s35 = "COMPRESSIONTYPES" fullword ascii
      $s36 = "KEEPCOMPRESSEDAS" fullword ascii
      $s37 = "APT::Get::Simulate" fullword ascii
      $s38 = "APT::Get::Print-URIs" fullword ascii
      $s39 = "Distribution upgrade, see apt-get(8)" fullword ascii
      $s40 = "for installation, upgrade and removal of packages together" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_logsave {
   strings:
      $s1 = "Usage: %s [-asv] logfile program" fullword ascii
      $s2 = "Backgrounding to save %s later" fullword ascii
      $s3 = "Log of " fullword ascii
      $s4 = " exited with status code %d" fullword ascii
      $s5 = "died with signal %d" fullword ascii
      $s6 = "520300e33796ef410c80dc398b17c321ca00ea.debug" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 40KB and
      all of them
}

rule false_negative_bins_perlbug {
   strings:
      $s1 = "    # Not OK - provide build failure template by finessing OK report" fullword ascii
      $s2 = "  -b    Body of the report. If not included on the command line, or" fullword ascii
      $s3 = "L<https://github.com/Perl/perl5/issues>. The B<perlbug@perl.org>" fullword ascii
      $s4 = "at https://github.com/Perl/perl5/issues" fullword ascii
      $s5 = "L<https://github.com/Perl/perl5/issues>" fullword ascii
      $s6 = "The GitHub issue tracker at https://github.com/Perl/perl5/issues is the" fullword ascii
      $s7 = "https://github.com/Perl/perl5/issues" fullword ascii
      $s8 = "may be able to use B<perlbug -d> or B<perl -V> to get system" fullword ascii
      $s9 = "  -T    Thank-you mode. The target address defaults to '$thanksaddress'." fullword ascii
      $s10 = "    print \"\\nReport saved to '$file'. Please submit it to https://github.com/Perl/perl5/issues\\n\";" fullword ascii
      $s11 = "Test mode.  Makes it possible to command perlbug from a pipe or file, for" fullword ascii
      $s12 = "my $config_tag1 = '5.36.0 - Sat Nov 25 20:59:54 UTC 2023';" fullword ascii
      $s13 = "    # Users address, used in message and in From and Reply-To headers" fullword ascii
      $s14 = "    eval 'exec /usr/bin/perl -S $0 ${1+\"$@\"}'" fullword ascii
      $s15 = "    if ( open my $sff_fh, '|-:raw', 'MCR TCPIP$SYSTEM:TCPIP$SMTP_SFF.EXE SYS$INPUT:' ) {" fullword ascii
      $s16 = "            $sendmail = \"$_/sendmail.exe\", last if -e \"$_/sendmail.exe\";" fullword ascii
      $s17 = "  -nok  Report unsuccessful build on this system to perl porters" fullword ascii
      $s18 = "If you wish to generate a bug report, please run it without the -T flag" fullword ascii
      $s19 = "  -v    Include Verbose configuration data in the report" fullword ascii
      $s20 = "for $entry on https://rt.cpan.org, and report your issue there." fullword ascii
      $s21 = "    # OK - send \"OK\" report for build on this system" fullword ascii
      $s22 = "https://perldoc.perl.org/perlcommunity.html" fullword ascii
      $s23 = "    \"It is being executed now by  Perl $config_tag2.\\n\\n\"" fullword ascii
      $s24 = "Neither is \"perl crashes\" nor is \"HELP!!!\".  These don't help.  A compact" fullword ascii
      $s25 = "in a file with B<-f>, you will get a chance to edit the report." fullword ascii
      $s26 = "this with B<-v> to get more complete data." fullword ascii
      $s27 = "    # read in the report template once so that" fullword ascii
      $s28 = "if 0; # ^ Run only under a shell" fullword ascii
      $s29 = "    # -------- Configuration ---------" fullword ascii
      $s30 = "submit or comment on) and the commit logs to development" fullword ascii
      $s31 = "$Getopt::Std::STANDARD_HELP_VERSION = 1;" fullword ascii
      $s32 = "        qw(PATH LD_LIBRARY_PATH LANG PERL_BADLANG SHELL HOME LOGDIR LANGUAGE);" fullword ascii
      $s33 = "    # Target address" fullword ascii
      $s34 = "        in a file with -f, you will get a chance to edit the report." fullword ascii
      $s35 = "$0  [-v] [-r returnaddress] [-ok | -okay | -nok | -nokay]" fullword ascii
      $s36 = "  -okay As -ok but allow report from old builds." fullword ascii
      $s37 = "  -nokay As -nok but allow report from old builds." fullword ascii
      $s38 = "        anything. You can use this with -v to get more complete data." fullword ascii
      $s39 = "B<perl5-porters@perl.org>.  When sending a patch, create it using" fullword ascii
      $s40 = "sub _read_report {" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 100KB and
      8 of them
}

rule false_negative_bins_xz {
   strings:
      $s1 = "Reduced the number of threads from %s to one. The automatic memory usage limit of %s MiB is still being exceeded. %s MiB of memo" ascii
      $s2 = "Reduced the number of threads from %s to one. The automatic memory usage limit of %s MiB is still being exceeded. %s MiB of memo" ascii
      $s3 = "Switching to single-threaded mode to not exceed the memory usage limit of %s MiB" fullword ascii
      $s4 = "Number of processor threads:" fullword ascii
      $s5 = "Reduced the number of threads from %s to %s to not exceed the memory usage limit of %s MiB" fullword ascii
      $s6 = "      --files[=FILE]  read filenames to process from FILE; if FILE is" fullword ascii
      $s7 = "Error creating a pipe: %s" fullword ascii
      $s8 = "Error getting the file status flags from standard output: %s" fullword ascii
      $s9 = "                      to use as many threads as there are processor cores" fullword ascii
      $s10 = "Error getting the file status flags from standard input: %s" fullword ascii
      $s11 = "Switching to single-threaded mode due to --flush-timeout" fullword ascii
      $s12 = "      --no-adjust     if compression settings exceed the memory usage limit," fullword ascii
      $s13 = "  -e, --extreme       try to improve compression ratio by using more CPU time;" fullword ascii
      $s14 = "The filter chain is incompatible with --flush-timeout" fullword ascii
      $s15 = "%s: Too many arguments to --block-list" fullword ascii
      $s16 = "%s: Invalid argument to --block-list" fullword ascii
      $s17 = "https://tukaani.org/xz/" fullword ascii
      $s18 = "                      decompressor memory usage into account before using 7-9!" fullword ascii
      $s19 = "Multi-threaded decompression:" fullword ascii
      $s20 = "Compression of lzip files (.lz) is not supported" fullword ascii
      $s21 = "%s: poll() failed: %s" fullword ascii
      $s22 = "  -S, --suffix=.SUF   use the suffix `.SUF' on compressed files" fullword ascii
      $s23 = "Sizes in headers:" fullword ascii
      $s24 = "Memory usage limits:" fullword ascii
      $s25 = " Operation mode:" fullword ascii
      $s26 = "lzma_get_progress" fullword ascii
      $s27 = "lzma_stream_encoder_mt_memusage" fullword ascii
      $s28 = "      --robot         use machine-parsable messages (useful for scripts)" fullword ascii
      $s29 = " Operation modifiers:" fullword ascii
      $s30 = "MemUsage" fullword ascii
      $s31 = "Default for -T0:" fullword ascii
      $s32 = "  -M, --memlimit=LIMIT" fullword ascii
      $s33 = "UncompOffset" fullword ascii
      $s34 = "  Minimum XZ Utils version: %s" fullword ascii
      $s35 = "Uncompressed size:" fullword ascii
      $s36 = "lzma_cputhreads" fullword ascii
      $s37 = "memlimit-mt-decompress" fullword ascii
      $s38 = "X@Unsupported LZMA1/LZMA2 preset: %s" fullword ascii
      $s39 = "Error restoring the status flags to standard input: %s" fullword ascii
      $s40 = " Basic file format and compression options:" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule false_negative_bins_flock {
   strings:
      $s1 = " -c, --command <command>  run a single command string through the shell" fullword ascii
      $s2 = " -F, --no-fork            execute command without forking" fullword ascii
      $s3 = " %1$s [options] <file>|<directory> -c <command>" fullword ascii
      $s4 = " -o, --close              close file descriptor before running command" fullword ascii
      $s5 = "--command" fullword ascii
      $s6 = "Manage file locks from shell scripts." fullword ascii
      $s7 = "%s: executing %s" fullword ascii
      $s8 = "failed to get lock" fullword ascii
      $s9 = "%s requires exactly one command argument" fullword ascii
      $s10 = "%s: getting lock took %ld.%06ld seconds" fullword ascii
      $s11 = " -s, --shared             get a shared lock" fullword ascii
      $s12 = "the --no-fork and --close options are incompatible" fullword ascii
      $s13 = "timeout while waiting to get lock" fullword ascii
      $s14 = " %1$s [options] <file descriptor number>" fullword ascii
      $s15 = "requires file descriptor, file or directory" fullword ascii
      $s16 = "waitpid failed" fullword ascii
      $s17 = " -E, --conflict-exit-code <number>  exit code after conflict or timeout" fullword ascii
      $s18 = " -x, --exclusive          get an exclusive lock (default)" fullword ascii
      $s19 = " %1$s [options] <file>|<directory> <command> [<argument>...]" fullword ascii
      $s20 = "invalid timeout value" fullword ascii
      $s21 = "invalid exit code" fullword ascii
      $s22 = " -n, --nonblock           fail rather than wait" fullword ascii
      $s23 = "shared" fullword ascii /* Goodware String - occured 165 times */
      $s24 = "fd7bb322f2f9daf9b6144353b71363992a81b6.debug" fullword ascii
      $s25 = "flock(1)" fullword ascii
      $s26 = "conflict-exit-code" fullword ascii
      $s27 = "+sexnoFuw:E:hV?" fullword ascii
      $s28 = "nonblocking" fullword ascii /* Goodware String - occured 1 times */
      $s29 = "exit code out of range (expected 0 to 255)" fullword ascii
      $s30 = "fork failed" fullword ascii /* Goodware String - occured 2 times */
      $s31 = "     --verbose            increase verbosity" fullword ascii
      $s32 = "not enough arguments" fullword ascii /* Goodware String - occured 2 times */
      $s33 = " -w, --timeout <secs>     wait for a limited amount of time" fullword ascii
      $s34 = " -u, --unlock             remove a lock" fullword ascii
      $s35 = "cannot set up timer" fullword ascii
      $s36 = "no-fork" fullword ascii
      $s37 = "fd7bb322f2f9daf9b6144353b71363992a81b6" ascii
      $s38 = "D$XL+t$@L+D$HL" fullword ascii
      $s39 = "%-26s%s" fullword ascii
      $s40 = "cannot open lock file %s" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_paste {
   strings:
      $s1 = "serial" fullword ascii /* Goodware String - occured 168 times */
      $s2 = "W(H;W0" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "A(H;A0" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "b214d9465477a3764500baa93c9f0ad3e08067.debug" fullword ascii
      $s5 = "delimiter list ends with an unescaped backslash: %s" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "  -z, --zero-terminated    line delimiter is NUL, not newline" fullword ascii
      $s7 = "each FILE, separated by TABs, to standard output." fullword ascii /* Goodware String - occured 2 times */
      $s8 = "  -s, --serial            paste one file at a time instead of in parallel" fullword ascii
      $s9 = "standard input is closed" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "  -d, --delimiters=LIST   reuse characters from LIST instead of TABs" fullword ascii
      $s11 = "Write lines consisting of the sequentially corresponding lines from" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "David M. Ihnat" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "b214d9465477a37645" ascii
      $s14 = "O(H;O0sAH" fullword ascii
      $s15 = "b214d9465477a3764500baa93c9f0ad3e08067" ascii
      $s16 = "W(H;W0r" fullword ascii
      $s17 = "baa93c9f0ad3e08067" ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_apt {
   strings:
      $s1 = "_Z10DoDownloadR11CommandLine" fullword ascii
      $s2 = "Usage: apt [options] command" fullword ascii
      $s3 = "_Z11DoChangelogR11CommandLine" fullword ascii
      $s4 = "_Z16ParseCommandLineR11CommandLine7APT_CMDPKP13ConfigurationPP9pkgSystemiPPKcPFbS0_EPFSt6vectorI19aptDispatchWithHelpSaISF_EEvE" fullword ascii
      $s5 = "apt is a commandline package manager and provides commands for" fullword ascii
      $s6 = "changelog" fullword ascii
      $s7 = "_Z7DoCleanR11CommandLine" fullword ascii
      $s8 = "_Z7DependsR11CommandLine" fullword ascii
      $s9 = "_Z13DoDistUpgradeR11CommandLine" fullword ascii
      $s10 = "_Z10DoBuildDepR11CommandLine" fullword ascii
      $s11 = "_ZN11CommandLineC1Ev" fullword ascii
      $s12 = "_ZN11CommandLineD1Ev" fullword ascii
      $s13 = "_Z5DoMooR11CommandLine" fullword ascii
      $s14 = "_Z9DoUpgradeR11CommandLine" fullword ascii
      $s15 = "_Z11EditSourcesR11CommandLine" fullword ascii
      $s16 = "_Z11ShowPackageR11CommandLine" fullword ascii
      $s17 = "_Z6PolicyR11CommandLine" fullword ascii
      $s18 = "_Z19DispatchCommandLineR11CommandLineRKSt6vectorINS_8DispatchESaIS2_EE" fullword ascii
      $s19 = "_Z9DoInstallR11CommandLine" fullword ascii
      $s20 = "_Z11DoAutoCleanR11CommandLine" fullword ascii
      $s21 = "_Z8DoUpdateR11CommandLine" fullword ascii
      $s22 = "_Z14ShowSrcPackageR11CommandLine" fullword ascii
      $s23 = "_Z8DoSourceR11CommandLine" fullword ascii
      $s24 = "search in package descriptions" fullword ascii
      $s25 = "_Z6DoListR11CommandLine" fullword ascii
      $s26 = "_Z19CheckIfSimulateModeR11CommandLine" fullword ascii
      $s27 = "_Z8DoSearchR11CommandLine" fullword ascii
      $s28 = "_Z8RDependsR11CommandLine" fullword ascii
      $s29 = "autoremove" fullword ascii
      $s30 = "autopurge" fullword ascii
      $s31 = "showsrc" fullword ascii
      $s32 = "rdepends" fullword ascii
      $s33 = "upgrade the system by removing/installing/upgrading packages" fullword ascii
      $s34 = "_ZN13Configuration3SetEPKcRKi" fullword ascii
      $s35 = "upgrade the system by installing/upgrading packages" fullword ascii
      $s36 = "_ZNK13Configuration5FindIEPKcRKi" fullword ascii
      $s37 = "/usr/lib/debug/.dwz/x86_64-linux-gnu/apt.debug" fullword ascii
      $s38 = "libapt-private.so.0.0" fullword ascii
      $s39 = "APTPRIVATE_0.0" fullword ascii
      $s40 = "_ZN13Configuration6CndSetEPKci" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 50KB and
      8 of them
}

rule false_negative_bins_setarch {
   strings:
      $s1 = "Execute command `%s'." fullword ascii
      $s2 = " -X, --read-implies-exec  turns on READ_IMPLIES_EXEC" fullword ascii
      $s3 = "READ_IMPLIES_EXEC" fullword ascii
      $s4 = "read-implies-exec" fullword ascii
      $s5 = " -R, --addr-no-randomize  disables randomization of the virtual address space" fullword ascii
      $s6 = " -F, --fdpic-funcptrs     makes function pointers point to descriptors" fullword ascii
      $s7 = "setarch" fullword ascii
      $s8 = "ADDR_COMPAT_LAYOUT" fullword ascii
      $s9 = "Switching on %s." fullword ascii
      $s10 = "failed to set personality to %s" fullword ascii
      $s11 = "Change the reported architecture and set personality flags." fullword ascii
      $s12 = " -L, --addr-compat-layout changes the way virtual memory is allocated" fullword ascii
      $s13 = "addr-compat-layout" fullword ascii
      $s14 = "%s: Unrecognized architecture" fullword ascii
      $s15 = "no architecture argument or personality flags specified" fullword ascii
      $s16 = " -3, --3gb                limits the used address space to a maximum of 3 GB" fullword ascii
      $s17 = "     --4gb                ignored (for backward compatibility only)" fullword ascii
      $s18 = "linux32" fullword ascii
      $s19 = "uname26" fullword ascii
      $s20 = "Kernel cannot set architecture to %s" fullword ascii
      $s21 = "UNAME26" fullword ascii
      $s22 = "fdpic-funcptrs" fullword ascii
      $s23 = "ADDR_LIMIT_32BIT" fullword ascii
      $s24 = "whole-seconds" fullword ascii
      $s25 = "+hVv3BFILRSTXZ" fullword ascii
      $s26 = "MMAP_PAGE_ZERO" fullword ascii
      $s27 = "ADDR_NO_RANDOMIZE" fullword ascii
      $s28 = "setarch(8)" fullword ascii
      $s29 = "FDPIC_FUNCPTRS" fullword ascii
      $s30 = "uname-2.6" fullword ascii
      $s31 = "SHORT_INODE" fullword ascii
      $s32 = "WHOLE_SECONDS" fullword ascii
      $s33 = "2a0388e35d18506b6bf3219316b81293be5f50.debug" fullword ascii
      $s34 = "sticky-timeouts" fullword ascii
      $s35 = "STICKY_TIMEOUTS" fullword ascii
      $s36 = "ADDR_LIMIT_3GB" fullword ascii
      $s37 = "unrecognized option '--list'" fullword ascii
      $s38 = "linux64" fullword ascii /* Goodware String - occured 1 times */
      $s39 = "addr-no-randomize" fullword ascii
      $s40 = "sparc32bash" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      8 of them
}

rule false_negative_bins_expand {
   strings:
      $s1 = "  -t, --tabs=LIST  use comma separated list of tab positions." fullword ascii
      $s2 = "src/expand-common.c" fullword ascii
      $s3 = "'/' specifier is mutually exclusive with '+'" fullword ascii
      $s4 = "'+' specifier not at start of number: %s" fullword ascii
      $s5 = "'/' specifier only allowed with the last value" fullword ascii
      $s6 = "next_file" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "prev_file" fullword ascii
      $s8 = "'+' specifier only allowed with the last value" fullword ascii
      $s9 = "aa76c725414f419f67a2c24d7254d6633b14f2.debug" fullword ascii
      $s10 = "'/' specifier not at start of number: %s" fullword ascii
      $s11 = "G(H;G0r" fullword ascii /* Goodware String - occured 2 times */
      $s12 = "it:0::1::2::3::4::5::6::7::8::9::" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "Convert tabs in each FILE to spaces, writing to standard output." fullword ascii /* Goodware String - occured 2 times */
      $s14 = "  -t, --tabs=N     have tabs N characters apart, not 8" fullword ascii
      $s15 = "  -i, --initial    do not convert tabs after non blanks" fullword ascii
      $s16 = "                     the last specified tab stop instead of the first column" fullword ascii
      $s17 = "tab size contains invalid character(s): %s" fullword ascii /* Goodware String - occured 4 times */
      $s18 = "                     to specify a tab size to use after the last" fullword ascii
      $s19 = "tab sizes must be ascending" fullword ascii /* Goodware String - occured 4 times */
      $s20 = "tab size cannot be 0" fullword ascii /* Goodware String - occured 4 times */
      $s21 = "aa76c725414f419f67a2c24d7254d6633b14f2" ascii
      $s22 = "input line is too long" fullword ascii /* Goodware String - occured 4 times */
      $s23 = "tab stop is too large %s" fullword ascii /* Goodware String - occured 4 times */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule unexpand {
   strings:
      $s1 = "  -t, --tabs=LIST  use comma separated list of tab positions." fullword ascii
      $s2 = "      --first-only  convert only leading sequences of blanks (overrides -a)" fullword ascii
      $s3 = "src/expand-common.c" fullword ascii
      $s4 = "'/' specifier is mutually exclusive with '+'" fullword ascii
      $s5 = "'+' specifier not at start of number: %s" fullword ascii
      $s6 = "'/' specifier only allowed with the last value" fullword ascii
      $s7 = "next_file" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "prev_file" fullword ascii
      $s9 = "'+' specifier only allowed with the last value" fullword ascii
      $s10 = "'/' specifier not at start of number: %s" fullword ascii
      $s11 = "8fc592b1a2a99a8e58e02f69fa84ad13e7f991.debug" fullword ascii
      $s12 = ",0123456789at:" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "  -a, --all        convert all blanks, instead of just initial blanks" fullword ascii
      $s14 = "first-only" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "Convert blanks in each FILE to tabs, writing to standard output." fullword ascii /* Goodware String - occured 2 times */
      $s16 = "  -t, --tabs=N     have tabs N characters apart instead of 8 (enables -a)" fullword ascii
      $s17 = "unexpand" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "tab stop value is too large" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "                     the last specified tab stop instead of the first column" fullword ascii
      $s20 = "tab size contains invalid character(s): %s" fullword ascii /* Goodware String - occured 4 times */
      $s21 = "                     to specify a tab size to use after the last" fullword ascii
      $s22 = "tab sizes must be ascending" fullword ascii /* Goodware String - occured 4 times */
      $s23 = "tab size cannot be 0" fullword ascii /* Goodware String - occured 4 times */
      $s24 = "input line is too long" fullword ascii /* Goodware String - occured 4 times */
      $s25 = "tab stop is too large %s" fullword ascii /* Goodware String - occured 4 times */
      $s26 = "0123456789a" ascii
      $s27 = "8fc592b1a2a99a8e58e02f69fa84ad13e7f991" ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule false_negative_bins_fold {
   strings:
      $s1 = "invalid number of columns" fullword ascii
      $s2 = "Wrap input lines in each FILE, writing to standard output." fullword ascii
      $s3 = "849e249c80e87eb15ffe112b2bd6bd0e592fff.debug" fullword ascii
      $s4 = "bsw:0::1::2::3::4::5::6::7::8::9::" fullword ascii /* Goodware String - occured 2 times */
      $s5 = "  -s, --spaces        break at spaces" fullword ascii
      $s6 = "  -b, --bytes         count bytes rather than columns" fullword ascii
      $s7 = "  -w, --width=WIDTH   use WIDTH columns instead of 80" fullword ascii
      $s8 = "849e249c80e87eb15ffe112b2bd6bd0e592fff" ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      all of them
}

