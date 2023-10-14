# vim: set et ai ts=4 sts=4 sw=4:
import logging

from . import keystore_to_file, keystore_from_file

LOG = logging.getLogger(__name__)


def ks_write(args):
    out_dict = dict(vars(args))
    for k in ("input", "output", "outpass"):
        del out_dict[k]

    myks = keystore_from_file(args.input, "", kwargs=out_dict)

    keystore_to_file(myks, args.output, args.outpass)
