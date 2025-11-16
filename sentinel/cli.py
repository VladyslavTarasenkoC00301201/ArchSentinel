import argparse
from sentinel.scanner.main import run_scanner

def main():
    parser = argparse.ArgumentParser(description="ArchSentinel Security Toolkit")
    parser.add_argument("command", choices=["scan-config"], help="Command to run")
    parser.add_argument("--mode", choices=["audit", "flexible-secure", "strict"], default="audit")
    parser.add_argument("--fix", action="store_true", help="Automatically fix insecure settings")

    args = parser.parse_args()

    if args.command == "scan-config":
        run_scanner(args.mode, args.fix)

if __name__ == "__main__":
    main()

