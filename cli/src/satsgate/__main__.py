"""Console entry: `satsgate` and `python -m satsgate`."""

from __future__ import annotations

import argparse
import sys

from satsgate import __version__
from satsgate.init import InitOptions, run_init
from satsgate_proxy import __version__ as proxy_version
from satsgate_sdk import __version__ as sdk_version


def version_line() -> str:
    return f"satsgate {__version__}\nsatsgate-sdk {sdk_version}\nsatsgate-proxy {proxy_version}\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="satsgate", description="Set up a self-hosted satsgate paywall.")
    parser.add_argument("--version", action="store_true", help="Print the satsgate, SDK, and proxy versions.")
    sub = parser.add_subparsers(dest="command")
    init = sub.add_parser("init", help="Write a paywall config for a Lightning Address.")
    init.add_argument("--json", action="store_true", help="Print one JSON object and do not prompt.")
    init.add_argument("--api-url", default=None, help="Core API URL. Defaults to SATSGATE_API_URL or the public API.")
    init.add_argument("--lightning-address", default=None, help="Lightning Address that receives payments.")
    init.add_argument("--want-usdc", action="store_true", help="Offer USDC test mode when the EVM payee is verified.")
    init.add_argument("--docker", action="store_true", help="Also write docker-compose.satsgate.yml.")
    init.add_argument(
        "--framework",
        choices=("fastapi", "express", "nginx", "none"),
        default=None,
        help="Origin check to copy next to the config.",
    )
    init.add_argument("--path", default="/paid/**", help="Route path. Default: /paid/**.")
    init.add_argument("--upstream", default="http://127.0.0.1:3000", help="Origin base URL.")
    init.add_argument(
        "--public-url",
        default="http://127.0.0.1:8080",
        help="Buyer-facing proxy URL used when USDC test mode is on. Buyers need a public URL.",
    )
    init.add_argument("--yaml-out", default=None, help="Config path. Default: satsgate-proxy.yaml.")
    init.add_argument("--new-account", action="store_true", help="Open another account even if one is saved.")
    init.add_argument(
        "--replace-lightning-address",
        action="store_true",
        help="Replace a different Lightning Address already saved on the account.",
    )
    return parser


def options_from(args: argparse.Namespace) -> InitOptions:
    want = True if args.want_usdc else None
    return InitOptions(
        api_url=args.api_url,
        lightning_address=args.lightning_address,
        want_usdc=want,
        json_mode=bool(args.json),
        docker=bool(args.docker),
        framework=args.framework,
        path=args.path,
        upstream=args.upstream,
        public_url=args.public_url,
        yaml_out=args.yaml_out,
        new_account=bool(args.new_account),
        replace_lightning_address=bool(args.replace_lightning_address),
    )


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        sys.stdout.write(version_line())
        return 0
    if args.command != "init":
        parser.print_help(sys.stderr)
        return 2
    return run_init(options_from(args))


def main(argv: list[str] | None = None) -> None:
    raise SystemExit(run(argv))


if __name__ == "__main__":
    main()
