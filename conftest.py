"""Keeps the project root importable so tests can import the wpsscanner package.

Without an installed package, pytest's default import mode only adds the
directory containing each test module to sys.path. The presence of this file
makes pytest add the project root as well, so plain ``pytest`` works.
"""
