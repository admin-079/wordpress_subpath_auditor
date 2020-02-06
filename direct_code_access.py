#!/usr/bin/python3
# -*- coding: utf-8 -*-

import glob
import click
import coloredlogs
import logging
import re

logger = logging.getLogger("WoSuAu")
coloredlogs.install(level='INFO', logger=logger)

rgx_abspath = r".*defined.*?ABSPATH.*?$"
rgx_comm_long = r"/\*.*?\*/"
rgx_comm_short = r".*//.*"

class DefaultHelp(click.Command):
    def __init__(self, *args, **kwargs):
        context_settings = kwargs.setdefault('context_settings', {})
        if 'help_option_names' not in context_settings:
            context_settings['help_option_names'] = ['-h', '--help']
        self.help_flag = context_settings['help_option_names'][0]
        super(DefaultHelp, self).__init__(*args, **kwargs)

    def parse_args(self, ctx, args):
        if not args:
            args = [self.help_flag]
        return super(DefaultHelp, self).parse_args(ctx, args)

@click.command(cls=DefaultHelp)
@click.option("-s", "--subdir", help="Subdir to audit", required=True, type=str)
@click.pass_context
def main(self, subdir):
    """\b
    Find out if a file contains direct executable php code. 
    Example command :
        python direct_code_access.py -s html/wp-content/plugins
    """
    print("<?php") # For syntax hilight... ;)
    files = glob.glob(subdir + "/**/*.php", recursive=True)
    for file in files:
        logger.debug(file)
        data = open(file, errors='ignore').read()

        # Remove /* */
        comm_long = re.findall(rgx_comm_long, data, re.DOTALL)
        for comm in comm_long:
            logger.debug(f"comm_long: {comm}")
            data = data.replace(comm, "")
        
        # Remove // 
        comm_short = re.findall(rgx_comm_short, data)
        for comm in comm_short:
            logger.debug(f"comm_short: {comm}")
            data = data.replace(comm, "")
        
        # remove <?php ?>
        data = data.replace("<?php", "")
        data = data.replace("?>", "")

        # Stop at ABSPATH check
        abspath = re.search(rgx_abspath, data)
        if abspath:
            data = data[:data.find(abspath.group())]
        

        data = "\n".join([line for line in data.splitlines() if len(line.strip()) != 0])
        data = data.replace("\t", "  ")
        if len(data) == 0:
            continue
        
        print(f"\n\n\n/*** Reachable code in {file} ***/\n")
        
        print(data)
    print("?>") # End of syntax hilight

if __name__ == '__main__':
    main()
