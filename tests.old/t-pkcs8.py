
import logging, sys
from pyktool import pkcs8

def main(args = sys.argv[1:]):
    logging.basicConfig(level=logging.DEBUG)

    with open(args[0], "rb") as data:
        print (pkcs8.pkcs8_load(data.read(), password=args[1].encode('ascii')))

if __name__ == '__main__':
    main()
