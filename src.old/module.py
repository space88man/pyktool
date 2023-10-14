#!/usr/bin/env python

"""
setup.py file for SWIG legacy
"""

from distutils.core import setup, Extension


legacy_module = Extension('_legacy',
                           sources=['legacy_wrap.c', 'legacy.c', 'twofish.c'],
                           libraries=['crypto']
                           )

setup (name = 'legacy',
       version = '0.2',
       author      = "SWIG Docs",
       description = """Simple swig legacy from docs""",
       ext_modules = [legacy_module],
       py_modules = ["legacy"],
       )
