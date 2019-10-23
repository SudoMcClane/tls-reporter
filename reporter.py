#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[Add module documentation here]

Author: Clément Gatefait
Date: 17/10/2019
"""

import argparse
import json
import sys


def printBanner():
    """Print the program banner in the standard output
    """
    banner = ('88888888888 888        ▄████▄       8888888b.                  '
              '                  888                    \n'
              '    888     888      ▄██▀  ▀██▄     888   Y88b                 '
              '                  888                    \n'
              '    888     888      ██      ██     888    888                 '
              '                  888                    \n'
              '    888     ▄▄▄▄▄▄▄▄▄██▄8b.         888   d88P .d88b.  88888b. '
              '  .d88b.  888d888 888888 .d88b.  888d888 \n'
              '    888     ██8  ▄▄▄   ▐"888b.      8888888P" d8P  Y8b 888 "88b'
              ' d88""88b 888P"   888   d8P  Y8b 888P"   \n'
              '    888     ██8  ▀█▀   ▐   "88b     888 T88b  88888888 888  888'
              ' 888  888 888     888   88888888 888     \n'
              '    888     ██8   ▀  Y8▐b  d88P     888  T88b Y8b.     888 d88P'
              ' Y88..88P 888     Y88b. Y8b.     888     \n'
              '    888     ████████▐███8888P"      888   T88b "Y8888  88888P" '
              '  "Y88P"  888      "Y888 "Y8888  888     \n'
              '                                                       888     '
              '                          __   _         \n'
              '                                                       888     '
              '                    __ __/  \\ / |        \n'
              '                                                       888     '
              '                    \\ V / () || |        \n'
              '                                                               '
              '                     \\_/ \\__(_)_|        \n')
    print("\n%s" % banner)


def parseArguments():
    """Parse commandline arguments.
    Returns an argparse.ArgumentParser object.
    """
    prog = 'reporter.py'
    description = ('A simple testssl result parser for report redactors. '
                   'Use the --jsonfile option when running testssl.sh and '
                   'put the created file as a program argument.')
    parser = argparse.ArgumentParser(prog=prog, description=description)
    parser.add_argument('infile', nargs='?', type=argparse.FileType(),
                        help='The JSON testssl output',
                        default=sys.stdin)
    parser.add_argument('outfile', nargs='?', type=argparse.FileType('w'),
                        help='write the output to outfile',
                        default=sys.stdout)
    parser.add_argument('--sort', action='store_true', default=False,
                        help='sort the output by severity')
    parser.add_argument('--level', type=str, default='WARN',
                        choices=['OK', 'INFO', 'WARN', 'LOW', 'MEDIUM', 'HIGH',
                                 'CRITICAL'],
                        help='Set a minimal reported severity')
    return parser.parse_args()


def processObj(obj, defs, level, minLevel):
    """Process an object of the findings list.
    Returns a dictionary containing "severity" and "detail".
    """
    for definition in defs:
        if definition["id"].lower() == obj["id"].lower():
            if (level[definition["severity"]] <= level[obj["severity"]]
               or minLevel == "OK"):
                return {"severity": obj["severity"],
                        "detail": definition["detail"] % obj}

    # definition not found
    return {"severity": "ERROR",
            "detail": "[ERROR] No definition entry for: %s" % obj["id"]}


def main():
    """Main function of the program.
    """
    options = parseArguments()  # Retrieve arguments
    printBanner()               # Print the banner
    infile = options.infile
    outfile = options.outfile
    sort = options.sort
    minLevel = options.level
    definitions = open("definitions.json", "r")     # Open the definitions file
    level = {"OK": -1, "INFO": 0, "WARN": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4,
             "CRITICAL": 5, "ERROR": 6}
    vulns = []  # Initialize the list of vulnerabilities to report

    with infile, outfile:
        try:
            objs = (json.load(infile), )[0]         # List of dictionaries
            defs = (json.load(definitions), )[0]    # List of dictionaries

            for obj in objs:    # foreach vulnerability scanned
                if level[minLevel] <= level[obj["severity"]]:   # --level test
                    # process the vulnerability and add it to the reported ones
                    vulns.append(processObj(obj, defs, level, minLevel))

            if sort:    # --sort implementation
                tmp = []
                for i in range(6, -2, -1):  # foreach severity descending
                    j = 0
                    while j < len(vulns):   # foreach vulnerability reported
                        if level[vulns[j]["severity"]] >= i:
                            tmp.append(vulns[j])
                            vulns.pop(j)    # remove for performance
                        else:
                            j += 1
                vulns = tmp

            for vuln in vulns:
                outfile.write("%s\n" % vuln["detail"])

        except ValueError as e:
            raise SystemExit(e)


if __name__ == '__main__':
    main()
