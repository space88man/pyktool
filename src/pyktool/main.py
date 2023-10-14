from __future__ import print_function

import sys
import base64
import logging
import argparse
from . import keystore_from_file, keystore_to_file, errors

LOG = logging.getLogger(__name__)


def ks_dump(args, nodump=False):
    out_dict = dict(vars(args))
    if args.driver:
        out_dict["driver"] = args.driver.split(",")
    else:
        out_dict["driver"] = []
    for k in ("input", "inpass", "func"):
        del out_dict[k]

    ks = None
    try:
        ks = keystore_from_file(args.input, args.inpass, out_dict)
        LOG.debug(
            f"ks_dump: input {len(ks.certs)} certs and {len(ks.private_keys)} private keys"
        )
    except Exception as exc:
        LOG.error("Failed to load keystore: %s", str(exc))
        raise exc

    if ks is not None and not nodump:
        base64.MAXBINSIZE = 48
        print(ks.pem_s(), end="")
    else:
        return ks, out_dict


def ks_convert(args):
    ks_in, out_dict = ks_dump(args, nodump=True)
    LOG.debug(
        f"ks_convert: input {len(ks_in.certs)} certs and {len(ks_in.private_keys)} private keys"
    )

    keystore_to_file(ks_in, args.output, args.outpass, out_dict)


def set_logging(level):
    logging.getLogger().setLevel(level)


def main(argv=sys.argv[1:]):
    """Entry point for the application script"""

    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser(prog="pyktool")
    parser.add_argument("--loglevel", default="INFO")
    parser.add_argument("--driver")
    subparsers = parser.add_subparsers()

    parser_dump = subparsers.add_parser("dump")
    parser_dump.add_argument("input")
    parser_dump.add_argument("inpass")
    parser_dump.add_argument("--alias")
    parser_dump.add_argument("--in_format")
    parser_dump.add_argument("--out_format")
    parser_dump.add_argument("--truststore", action="store_true")
    parser_dump.set_defaults(func=ks_dump)

    parser_cvt = subparsers.add_parser("convert")
    parser_cvt.add_argument("input")
    parser_cvt.add_argument("inpass")
    parser_cvt.add_argument("output")
    parser_cvt.add_argument("outpass")
    parser_cvt.add_argument("--alias")
    parser_cvt.add_argument("--in_format")
    parser_cvt.add_argument("--out_format")
    parser_cvt.add_argument("--truststore", action="store_true")
    parser_cvt.set_defaults(func=ks_convert)

    args = parser.parse_args(argv)
    if args.alias:
        args.alias = args.alias.split(",")
    else:
        args.alias = []

    set_logging(args.loglevel)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
