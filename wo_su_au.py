#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Common variables

from base64 import b64decode, b64encode
from enum import Enum
from glob import glob
from json import loads
from parsel import Selector
from re import compile, search, findall
from requests import get
from sources_n_sinks import targets, TYPE_SOURCE, TYPE_SINK
from subprocess import run
from sys import exit
from termcolor import colored
from time import sleep
from urllib.parse import urlparse

import click
import coloredlogs
import logging

logger = logging.getLogger("WoSuAu")

FEATURES = ["CR", "ST", "UR", "PA"]
JSON_SPLIT = "**********JSON_SPLIT**********"
PHP_DEL = "// WOPLAU_REMOVE"
DISABLED = "Disabled"
DISABLED_B64 = b64encode(DISABLED.encode())


class Finding:
    def __init__(self, fct_params, fct_code, sinks, sources, used_urls, stacktraces):
        self.fct_params = fct_params
        self.fct_code = fct_code
        self.sinks = sinks
        self.sources = sources
        self.used_urls = used_urls
        self.stacktraces = stacktraces

    def __repr__(self):
        return f"{self.fct_params}, {self.fct_code}, {self.sinks}, {self.sources}, {self.used_urls}, {self.stacktraces}"


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
@click.option("-m", "--manual-action", help="Pause the tool to add extra manual actions", required=False, flag_value=True, default=False, type=bool)
@click.option("-d", "--disable", help="Disable designed features (CR)awl, (ST)acktrace, (UR)ls, (PA)rameters, multiple delimiter is , ", required=False, default="", type=str)
@click.option("-s", "--subdir", help="Subdir to audit, defaults to all plugins", required=False, default="html/wp-content/plugins/", type=str)
@click.option("-u", "--url", help="URLs to crawl, (identical hostnames), multiple delimiter is ,", required=True, type=str)
@click.option("-f", "--whitelisted-functions", help="Avoid code instrumentation for useless or broken functions, multiple delimiter=','", required=False, default="", type=str)
@click.option("-c", "--cookie", help="Specify a cookie for authenticated crawls", default=None, required=False, type=str)
@click.option("-D", "--debug", help="Enable debugging output", required=False, flag_value=True, default=False, type=bool)
@click.pass_context
def main(self, manual_action, disable, subdir, url, whitelisted_functions, cookie, debug):
    """\b
    Wordpress Subdir Editor, detect dynamically accesible sources and sinks, then, read the code ! :)
    Example command :
    python wo_su_au.py -u http://lokal:8000/ \\
        -s html/wp-content/plugins \\
        -d ST \\
        -c "COOKIE_NAME=COOKIE_VALUE"
    """

    if debug:
        coloredlogs.install(logger=logger, level=logging.DEBUG)
    else:
        coloredlogs.install(logger=logger, level=logging.INFO)
        
    # Clean previous findings, deinstrument for a clean scan
    run(["git", "checkout", "."], cwd="html")
    run(["touch", "html/logs.txt"])
    run(["chmod", "777", "html/logs.txt"])
    
    # Disabled features
    if len(disable) != 0:
        disable = disable.upper()
        disabled_features = set(disable.split(
            ",")) if "," in disable else {disable}

        for disabled_feature in disabled_features:
            if disabled_feature not in FEATURES:
                logger.error(f"Unknown feature : {disabled_feature}")
    else:
        disabled_features = list()

    # Crawler
    to_visit = set(url.split(",")) if "," in url else {url}
    sample_url = urlparse(next(iter(to_visit)))
    if len(whitelisted_functions) != 0:
        whitelisted_functions = set(whitelisted_functions.split(
            ",")) if "," in url else {whitelisted_functions}

    logger.debug(f"to_visit - {to_visit}")
    logger.debug(f"whitelisted_functions - {whitelisted_functions}")

    visited = set()
    fails = set()
    hostname = sample_url.hostname
    port = sample_url.port

    def visit(url):
        if "CR" in disabled_features:
            return
        logger.info(
            f"[{len(visited):>03} / {(len(to_visit) + len(visited)):>03}] - {url}")
        try:
            response = get(url, headers={'Cookie': cookie}, verify=False)
            visited.add(url)
            selector = Selector(response.text)
            links = set(selector.xpath('//*/@href').getall())
            for link in links:
                # Fix white spaces and dirty slashes (\\/) in urls
                link = link.strip().replace("\\", "").replace("\"", "").replace("'", "")
                # whitelisted domain only, and adjust port number
                if not hostname in link:
                    continue
                link = link.replace(f"{hostname}/", f"{hostname}:{port}/")
                # remove anchors
                if link.startswith("#"):
                    continue
                if "#" in link:
                    link = link.split("#")[0]
                # Prevent authenticated scan to logout
                if "logout" in link:
                    continue
                if not link in visited:
                    to_visit.add(link)
        except Exception as e:
            fails.add(url)
            logger.error(e)
            pass
        finally:
            if len(to_visit) != 0:
                visit(to_visit.pop())

    def disp(title, items):
        logger.error(f" {title} ".center(80, "*"))
        for item in items:
            logger.error(item)

    visit(to_visit.pop())

    visited = sorted(visited)
    logger.info(f"Crawled {len(visited)} links")

    if len(fails) != 0:
        disp("Fails", sorted(fails))

    # Instrument the code
    logger.info(f"Patching files from {subdir}")

    files = glob(subdir + "/**/*.php", recursive=True)
    fct_decl_regex = compile("function .*{")
    fct_name_regex = compile(" .*?\(")

    for file in files:
        logger.info(file)
        with open(file, "r+", errors='ignore') as f:
            content = f.read().strip().split("\n")
            for i in range(len(content)):
                line = content[i]

                if not " function " in line:
                    continue
                if line.strip().startswith("//") or line.strip().startswith("*"):
                    continue
                match = fct_decl_regex.search(line)
                if match:
                    logger.debug("match >" + str(match))
                    fct_decl = match.group()
                    logger.debug(f"fct_decl - {fct_decl}")
                    match = fct_name_regex.search(fct_decl)
                    fct_name = match.group().replace(" ", "").replace("(", "")
                    logger.debug(f"fct_name - {fct_name}")
                    fct_params = fct_decl[fct_decl.find(
                        "(")+1: fct_decl.rfind(")")].strip()
                    logger.debug(f"fct_params - {fct_params}")
                    param = compile("\$[a-zA-Z_]*")
                    cleaned_params = ", ".join(param.findall(fct_params))
                    logger.debug(f"cleaned_params - {cleaned_params}")

                    if fct_name == "" or fct_name in whitelisted_functions:
                        continue

                    ST = "//" if "ST" in disabled_features else ""
                    PA = "//" if "PA" in disabled_features else ""
                    UR = "//" if "UR" in disabled_features else ""
                    php_logger = f"""
    if (@get_class() != "") {{ $WoSuAu_func = new \ReflectionMethod(get_class(), '{fct_name}'); {PHP_DEL}
    }} else {{ $WoSuAu_func = new \ReflectionFunction('{fct_name}'); }} {PHP_DEL}
    $WoSuAu_filename = $WoSuAu_func->getFileName(); {PHP_DEL}
    $WoSuAu_start_line = $WoSuAu_func->getStartLine() - 1; {PHP_DEL}
    $WoSuAu_end_line = $WoSuAu_func->getEndLine(); {PHP_DEL}
    $WoSuAu_length = $WoSuAu_end_line - $WoSuAu_start_line; {PHP_DEL}
    $WoSuAu_source = file($WoSuAu_filename); {PHP_DEL}
    $WoSuAu_lines = array_slice($WoSuAu_source, $WoSuAu_start_line, $WoSuAu_length); {PHP_DEL}
    foreach ($WoSuAu_lines as $WoSuAu_key => $WoSuAu_element) {{ if (strpos($WoSuAu_element, '{PHP_DEL}') !== false) {{ unset($WoSuAu_lines[$WoSuAu_key]); }} }} {PHP_DEL}
    $WoSuAu_body = implode("", $WoSuAu_lines); {PHP_DEL}
    {ST}$WoSuAu_e = new \Exception(); {PHP_DEL}
    $WoSuAu_log_line = "\\n\\n{JSON_SPLIT}\\n{{"; {PHP_DEL}
    $WoSuAu_log_line = $WoSuAu_log_line . '"fct_name": \"{fct_name}\", '; {PHP_DEL}
    {PA}$WoSuAu_log_line = $WoSuAu_log_line . '"fct_params": "' . base64_encode(json_encode(array({cleaned_params}))) . '",'; {PHP_DEL}
    {UR}$WoSuAu_log_line = $WoSuAu_log_line . '"used_url": "' . base64_encode($_SERVER['REQUEST_URI']) . '",'; {PHP_DEL}
    {ST}$WoSuAu_log_line = $WoSuAu_log_line . '"stacktrace": "' . base64_encode($WoSuAu_e->getTraceAsString()) . '",'; {PHP_DEL}
    $WoSuAu_log_line = $WoSuAu_log_line . '"fct_code": "' . base64_encode($WoSuAu_body) . '"}}'; {PHP_DEL}
    file_put_contents('/var/www/html/logs.txt', $WoSuAu_log_line, FILE_APPEND | LOCK_EX); {PHP_DEL}
    """

                    logger.debug(f"php_logger - {php_logger}")
                    new_line = line.replace("{", "{" + php_logger)
                    content[i] = new_line
            f.seek(0)
            f.truncate()
            new_file = "\n".join(content)
            logger.debug(f"new_file - {new_file}")
            f.write(new_file)

    logger.info(f"Wait a few seconds for docker to update wordpress filesystem")
    sleep(2)

    if manual_action or "CR" in disabled_features:
        input("Paused, add extra manual actions the wordpress action (login, post, delete, ...)")

    logger.info(f"Fetching crawled links to populate the logs")

    for url in visited:
        response = get(url, headers={'Cookie': cookie}, verify=False)
        logger.info(f"{response.status_code} - {url}")

    
    # Parse logged calls
    with open("html/logs.txt", "r") as f:
        logs = f.read().strip()

    #run(["git", "checkout", "."], cwd="html")

    logs = logs.split(JSON_SPLIT)[1:]
    logs = [log.strip() for log in logs]
    for i in range(len(logs)):
        try:
            logs[i] = loads(logs[i])
        except Exception as e:
            logger.error(f"Logline: {type(logs[i])}")
            logger.error(f"Logline: >{logs[i]}<")
            logger.error(e)

    functions = dict()
    for log in logs:
        if log["fct_name"] in functions:
            functions[log["fct_name"]].used_urls.add(
                b64decode(log.get("used_url", DISABLED)).decode())
            functions[log["fct_name"]].stacktraces.add(
                b64decode(log.get("stacktrace", DISABLED_B64)).decode().replace('\\n', '\n'))
        else:
            functions[log["fct_name"]] = Finding(
                b64decode(log.get("fct_params", DISABLED)).decode(),
                b64decode(log["fct_code"]).decode(),
                list(),
                list(),
                set([b64decode(log.get("used_url", DISABLED)).decode()]),
                set([b64decode(log.get("stacktrace", DISABLED_B64)).decode().replace('\\n', '\n')]))

    logger.info("Analysis completed!")
    for fct_name, fct_attrs in functions.items():
        print("\n" + f" {fct_name} ".center(80, '*'))
        for target in targets:
            if target.name in fct_attrs.fct_code.replace(" ", ""):
                if target.target_type == TYPE_SINK:
                    fct_attrs.sinks.append(target)
                if target.target_type == TYPE_SOURCE:
                    fct_attrs.sources.append(target)

        if len(fct_attrs.sinks) == len(fct_attrs.sources) == 0:
            continue

        print(f"Used urls:")
        for url in sorted(fct_attrs.used_urls):
            print(f"\t- {url}")
        print(f"Stacktraces:")
        for stacktrace in sorted(fct_attrs.stacktraces):
            print(f"\t- {stacktrace}")
        colored_code = fct_attrs.fct_code
        colored_code = "\n".join(
            [s for s in colored_code.split("\n") if s.strip()])
        print(f"Sinks found:")
        for sink in fct_attrs.sinks:
            print(f"\t- {sink.category} - {colored(sink.name, 'red')}")
            colored_code = colored_code.replace(
                sink.name, colored(sink.name, "red"))
        print(f"Sources found:")
        for source in fct_attrs.sources:
            print(f"\t- {source.category} - {colored(source.name, 'green')}")
            colored_code = colored_code.replace(
                source.name, colored(source.name, "green"))
        print(f"Parameters found:")
        for fct_param in [fct_attrs.fct_params]:
            print(f"\t- {fct_param}")
        print(f"\n{colored_code}")


if __name__ == '__main__':
    main()
