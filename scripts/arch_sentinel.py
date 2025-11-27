#!/usr/bin/env python3

import cmd
import shlex
import subprocess
import sys
import os




# Load banner from file next to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BANNER_PATH = os.path.join(SCRIPT_DIR, "banner.txt")

try:
    with open(BANNER_PATH, "r", encoding="utf-8") as f:
        SENTINEL_BANNER = f.read()
except FileNotFoundError:
    SENTINEL_BANNER = "ArchSentinel\n"  # simple fallback


def run_module(module_name: str, arg: str = ""):
    """Run a Python module as a subprocess, passing through any args string."""
    cmdline = [sys.executable, "-m", module_name]
    if arg:
        cmdline.extend(shlex.split(arg))
    result = subprocess.run(cmdline)
    if result.returncode != 0:
        print(f"{module_name} exited with code {result.returncode}")


class SentinelShell(cmd.Cmd):
    intro = SENTINEL_BANNER +  "ArchSentinel interactive shell. Type 'help' or 'help <command>'."
    prompt = "archsentinel> "


    def do_scan(self, arg):
        """
        Run the configuration scanner.

        Usage:
          scan --scan ssh
          scan --scan-all
          scan --scan ssh -j
          scan --scan-all -j report.json
        """
        run_module("scanner.run_scan", arg)


    def help_scan(self):
        print(self.do_scan.__doc__)


    def do_exit(self, arg):
        """Exit ArchSentinel shell."""
        print("Exiting ArchSentinel.")
        return True


    def do_quit(self, arg):
        """Exit ArchSentinel shell."""
        return self.do_exit(arg)


    def emptyline(self):
        # Do nothing when user presses Enter on empty line
        pass


    # Example placeholder for future enforcer command
    def do_enforce(self, arg):
        """
        Run configuration enforcer based on vuln_configs.json.

        This will require root:
          sudo python3 sentinel.py
          archsentinel> enforce
        """
        if os.geteuid() != 0:
            print("Enforcer will require root. Please run ArchSentinel with sudo.")
            return
        run_module("enforcer.run_enforcer")


    def do_logs(self, arg):
        """
        Run the log analyzer

        Examples:
            logs
            logs --view compact
            logs --rules ssh_invali_user,sudo_any_root_chain,... (use to choose which rulse will be applied  )
            logs --no-debug 
        """
        run_module("logs.log_analyzer", arg)


    def help_logs(self):
        print(self.do_logs.__doc__)


def main():
    shell = SentinelShell()
    shell.cmdloop()


if __name__ == "__main__":
    main()

