


# import matplotlib.pyplot as plt
# import numpy as np
from itertools import chain
from jinja2 import Template
import argparse

import os
import platform
import sys
import pathlib

import logging
# logging.basicConfig(filename='cat-dog.log',level=logging.DEBUG)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.FileHandler("{0}/{1}.log".format('.', 'cat-dog')),
        logging.StreamHandler()
    ])


import jupyter_core

# from owlready2 import *
from stix2 import *
from stix2 import FileSystemSource as fs
from stix2 import Filter
from stix2.utils import get_type_from_id

from pyxsb import pyxsb_start_session, pyxsb_end_session, pyxsb_command, \
                  pyxsb_query, XSBFunctor, XSBVariable, xsb_to_json, json_to_xsb

from pyxsb import *


sys.path.append('..')


# MulVal Data Loading
# BASE_DIR = '/opt/projects/diss/jupyter_nbs/mine'
BASE_DIR = '/opt/projects/diss/py-mulval'
DATA_DIR = 'data'
WORKING_DIR = '/'.join((BASE_DIR, DATA_DIR, 'test_003'))

XSB_ARCH_DIR = '/opt/apps/xsb/XSB/config/x86_64-unknown-linux-gnu'

## port MulVals graph_gen.sh to python
MULVALROOT = '/opt/mulval'
INTERACTIONRULES = '/'.join((MULVALROOT, 'kb/interaction_rules.P'))
INTERACTIONRULES_CVSS = '/'.join((MULVALROOT, 'kb/interaction_rules_with_metrics.P'))
RULES_WITH_METRIC_ARTIFACTS = '/'.join((MULVALROOT, 'kb/interaction_rules_with_metric_artifacts.P'))

_RULE_FILES = list()
_RULE_FILES_ADDITIONAL = list()

RUNNING_RULES_NAME = WORKING_DIR + '/running_rules.P'
ENV_FILE_NAME = WORKING_DIR + '/environment.P'
RUN_FILE_NAME = WORKING_DIR + '/run.P'

trace_option = 'completeTrace2'

INPUT_FILE = WORKING_DIR + '/input.P'

# os.chdir(WORKING_DIR)


class graph_gen(object):


    def __init__(self, *args, **kwargs):
        super(graph_gen, self)


    def graph_gen(self, *args, **kwargs):
        """
        do the things graph_gen.sh does
        this should leave a trace_output.P
        file in cwd that gets sent to attack_graph.cpp
        """
        _input_file = INPUT_FILE if 'input_file' not in kwargs else kwargs.get('input_file')
        _MULVALROOT = MULVALROOT  # if 'MULVALROOT' not in kwargs else kwargs.get('MULVALROOT')
        _type = None  # if 'type' not in kwargs else kwargs.get('type')  # 'run' | 'environment' includes the mulval_run line
        _tracemode = 'completeTrace2' if 'tracemode' not in kwargs else kwargs.get('tracemode')
        _dynamic_file = None
        _trim = False  # True is --trim | -tr flags passed
        _trim_rules = MULVALROOT + '/src/analyzer/advances_trim.P'
        _no_trim_rules = MULVALROOT + '/src/analyzer/advances_notrim.P'
        _cvss = False  # original script tests if this is zero (-z $CVSS) so this is probably a path not bool
        _goal = None  # goal passed in a flag
        # template this out for later
        # vars:

        ts = """
    :-['{{ _MULVALROOT }}/lib/libmulval'].  % start base run script
    :-['{{ _MULVALROOT }}/src/analyzer/translate'].
    :-['{{ _MULVALROOT }}/src/analyzer/attack_trace'].
    :-['{{ _MULVALROOT }}/src/analyzer/auxiliary'].

    :-dynamic meta/1.

    :-load_dyn('running_rules.P').

    :-load_dyn('{{_input_file}}').

    :-assert(traceMode({{_tracemode}})).  % end base run script

    % set if dynamic changes file is set (-d flag)
    {{':-load_dyn({{_dynamic_file}}).
    :-apply_dynamic_changes.' if _dynamic_file }}

    % set if --trim | -tr flag passed
    {% if _trim %}
    :-load_dyn('{{_trim_rules}}').                                                                                                                            
    :-tell('edges').
    :-writeEdges.
    :-told.
    :-shell('rm -f dominators.P').
    :-shell('dom.py edges dominators.P').
    :-loadDominators('dominators.P'). 
    {% else %}
    % else set if no --trim | -tr flag passed
    :-load_dyn('{{_no_trim_rules }}'). 
    {% endif %}

    % add this line if CVSS flag is not set (non-zero len) 
    % @TODO should expect a string here not bool
    {{':-assert(cvss(_, none)).' if not _cvss}}

    % add goal if passed as a flag
    {{':- assert(attackGoal(_goal)).' if _goal }}

    % add mulval run if we're not writing the environment program
    {{':-mulval_run.' if _type == 'run' }}

    """

        logging.info('writing rule file %s...' % RUNNING_RULES_NAME)
        _RULE_FILES.append(INTERACTIONRULES)  # @TODO cvss and ma checks
        self.writeRulesFile(_RULE_FILES, _RULE_FILES_ADDITIONAL)

        logging.info('writing environment file %s...' % ENV_FILE_NAME)
        tm = Template(ts)
        # logging.debug(locals())
        self.writeFile(ENV_FILE_NAME, tm.render(locals()))

        logging.info('writing run file %s...' % RUN_FILE_NAME)
        self.writeFile(RUN_FILE_NAME, tm.render(locals(), _type='run'))

        logging.info('running mulval in xsb...')
        os.chdir(WORKING_DIR)
        self.runMulVal()

    def writeRulesFile(self, _RULE_FILES, _RULE_FILES_ADDITIONAL):
        """@TODO needs logic for placement, tabling, validation"""

        with open(RUNNING_RULES_NAME, 'w+') as outfile:
            for fname in chain(_RULE_FILES, _RULE_FILES_ADDITIONAL):
                with open(fname, 'r') as infile:
                    outfile.write(infile.read())

    def writeFile(self, file_name, file_text, mode='w+'):
        '''
        w  write mode
        r  read mode
        a  append mode
        w+  create file if it doesn't exist and open it in (over)write mode
            [it overwrites the file if it already exists]
        r+  open an existing file in read+write mode
        a+  create file if it doesn't exist and open it in append mode
        '''
        with open(file_name, mode) as file:
            file.write(file_text)

    def runMulVal(self):
        pyxsb_start_session(XSB_ARCH_DIR)
        #     from pyxsb import *
        logging.info(pyxsb_query('cwd(D).'))d


        pyxsb_query('catch(abort,Exception,true).')

        # xsb 2>xsb_log.txt 1>&2 <<EOF
        # [environment].
        # tell('goals.txt').
        # writeln('Goal:').
        # iterate(attackGoal(G),
        #         (write(' '), write_canonical(G), nl)).
        # told.
        # # tabling breaks the  pyxsb_command but works with lowlevel api :?
        # UPDATE: 3.7 fails... rolling back to 3.6 works
        # TODO: clean up
        c2p_functor(b"consult", 1, reg_term(1))
        c2p_string(b"environment", p2p_arg(reg_term(1), 1))
        xsb_command()

        c2p_functor(b"tell", 1, reg_term(1))
        c2p_string(b"goals.txt", p2p_arg(reg_term(1), 1))
        xsb_command()

        pyxsb_command('writeln("Goal:"). ')

        c2p_functor(b"iterate", 1, reg_term(1))
        c2p_string(b"attackGoal(G),(write(' '), write_canonical(G), nl)", p2p_arg(reg_term(1), 1))
        xsb_command()
        pyxsb_command('told.')
        #     pyxsb_end_session()

        #     pyxsb_start_session(XSB_ARCH_DIR)
        c2p_functor(b"consult", 1, reg_term(1))
        c2p_string(b"run", p2p_arg(reg_term(1), 1))
        xsb_command()
        #     pyxsb_command('[run].')

        pyxsb_end_session()

def parseFlags():

    arg_parser = argparse.ArgumentParser(description='Process MulVal flags')
    arg_parser.add_argument('--rulefile', '-r', action='append',  # allow multiple rule files
                            help='add rulefile(s) -r rulefile.txt')
    arg_parser.add_argument('--additional', '-a', action='append',  # allow multiple rule files
                            help='add additional rulefile(s) -a anotherrulefile.txt')
    arg_parser.add_argument('--constraint', '-c', action='append',  # allow multiple rule files
                            help='add constraint files(s) -c constraintfile.txt')
    arg_parser.add_argument('--goal', '-g', action='append',  # allow multiple goals
                            help='add goals -g goal')
    arg_parser.add_argument('--dynamic', '-d', action='append',  # allow multiple dynamic files
                            help='add dynamic files -d dynamicfile.txt')
    arg_parser.add_argument('--visualize', '-v', help='create viz (implies csv output)', action='store_true')
    arg_parser.add_argument('-l', help='CSV OUTPUT', action='store_true')
    #     arg_parser.add_argument('viz_options', choices=['--arclabel', '--reverse', '--simple', '--nometric']), action='append'
    arg_parser.add_argument('--arclabel', help='viz_options', action='store_true')
    arg_parser.add_argument('--reverse', help='viz_options', action='store_true')
    arg_parser.add_argument('--simple', help='viz_options', action='store_true')
    arg_parser.add_argument('--nometric', help='viz_options', action='store_true')

    arg_parser.add_argument('--sat', '-s', help='SAT', action='store_true')
    arg_parser.add_argument('--satgui', '-sg', help='SAT GUI', action='store_true')
    arg_parser.add_argument('--trace', '-t', help='trace option')
    arg_parser.add_argument('--trim', '-tr', help='trim option', action='store_true')
    arg_parser.add_argument('--trimdom', '-td', help='trimdom option', action='store_true')
    arg_parser.add_argument('--cvss', help='cvss option', action='store_true')
    arg_parser.add_argument('-ma', help='metric artifacts', action='store_true')
    ### @TODO figure out what all these do...

    # args, other_args = arg_parser.parse_known_args()
    # print('args: ', args)
    # print('other args: ', other_args)

    return arg_parser.parse_known_args()


def setup_test_dir():
    """
    creates the files in WORKING_DIR needed to run py-mulval tests
    :return:
    """
    logging.debug(('creating working directory: %s') % (WORKING_DIR))
    pathlib.Path(WORKING_DIR).mkdir(parents=True, exist_ok=True)

    input_p = """attackerLocated(internet).
attackGoal(execCode(workStation,_)).

hacl(internet, webServer, tcp, 80).
hacl(webServer, _,  _, _).
hacl(fileServer, _, _, _).
hacl(workStation, _, _, _).
hacl(H,H,_,_).

/* configuration information of fileServer */
networkServiceInfo(fileServer, mountd, rpc, 100005, root).
nfsExportInfo(fileServer, '/export', _anyAccess, workStation).
nfsExportInfo(fileServer, '/export', _anyAccess, webServer).
vulExists(fileServer, vulID, mountd).
vulProperty(vulID, remoteExploit, privEscalation).
localFileProtection(fileServer, root, _, _).

/* configuration information of webServer */
vulExists(webServer, 'CAN-2002-0392', httpd).
vulProperty('CAN-2002-0392', remoteExploit, privEscalation).
networkServiceInfo(webServer , httpd, tcp , 80 , apache).

/* configuration information of workStation */
nfsMounted(workStation, '/usr/local/share', fileServer, '/export', read).
"""
    with open(INPUT_FILE, 'w+') as file:
        file.write(input_p)
    logging.debug(('creating input file: %s') % INPUT_FILE)



# if __name__ == "__main__":
def Main():
    mulval_args, attackgraph_args = parseFlags()
    logging.debug('Parsed mulval args: %s' % mulval_args)
    logging.debug('Parsed attack graph args:logPath %s' % attackgraph_args)

    setup_test_dir()

    gg = graph_gen()

    gg.graph_gen()