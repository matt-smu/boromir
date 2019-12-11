


# import matplotlib.pyplot as plt
# import numpy as np
from itertools import chain
from jinja2 import Template
import argparse
import re

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

# from pyxsb import pyxsb_start_session, pyxsb_end_session, pyxsb_command, pyxsb_query, XSBFunctor, XSBVariable, xsb_to_json, json_to_xsb

from pyxsb import *

from genTransMatrix import *


sys.path.append('..')

SEP = os.path.sep

# needed if pyxsb can't find xsb
XSB_ARCH_DIR = '/opt/apps/xsb/XSB/config/x86_64-unknown-linux-gnu'

## port MulVals graph_gen.sh to python

# MulVal Install Files
# MULVALROOT = '/opt/mulval'
MULVALROOT = '/opt/projects/diss/mulval/mulval'
INTERACTIONRULES = SEP.join((MULVALROOT, 'kb/interaction_rules.P'))
INTERACTIONRULES_CVSS = SEP.join((MULVALROOT, 'kb/interaction_rules_with_metrics.P'))
RULES_WITH_METRIC_ARTIFACTS = SEP.join((MULVALROOT, 'kb/interaction_rules_with_metric_artifacts.P'))
ATTACK_GRAPH_BIN = SEP.join((MULVALROOT, "bin/attack_graph"))

# MulVal Data Loading
# BASE_DIR = '/opt/projects/diss/jupyter_nbs/mine'
INPUT_FILE_NAME = 'input.P'
INPUT_BASE_NAME = os.path.splitext(INPUT_FILE_NAME)[0]
TRACE_MODE = 'completeTrace2'
BASE_DIR = '/opt/projects/diss/py-mulval'
DATA_DIR = SEP.join((BASE_DIR, 'data'))
WORKING_DIR = SEP.join((DATA_DIR, 'test_003'))
INPUT_FILE = SEP.join((WORKING_DIR, INPUT_FILE_NAME))

RUNNING_RULES_NAME = SEP.join((WORKING_DIR, 'running_rules.P'))
ENV_FILE_NAME = SEP.join((WORKING_DIR, 'environment.P'))
RUN_FILE_NAME = SEP.join((WORKING_DIR, 'run.P'))

_RULE_FILES = list()
_RULE_FILES_ADDITIONAL = list()

# Output vars
RESULTS_DIR = SEP.join((WORKING_DIR, 'output'))
MATRIX_FILE_NAME= INPUT_BASE_NAME + '.csv'
MATRIX_FILE = SEP.join((RESULTS_DIR, MATRIX_FILE_NAME))





# os.chdir(WORKING_DIR)


class attack_graph(object):

    def __init__(self, *args, **kwargs):
        super(attack_graph, self)

    def attack_graph(self, *args, **kwargs):
        """
        cerr << "Usage: attack_graph [options] tracefile_name" << endl;
        cerr << "Options: " << endl;
        cerr << "    -l:  List nodes and arcs as separate files." << endl;
        cerr << "    -p:  Only output simple paths." << endl;
        cerr << "    -t:  Test mode." << endl;
        cerr << "    -s:  Run SAT solver." << endl;
        """
        # subprocess.run([ATTACK_GRAPH_BIN, "trace_output.P"], stdout=subprocess.PIPE)
        # subprocess.run([ATTACK_GRAPH_BIN,"-l", "trace_output.P", ">", './AttackGraph.txt'], shell=True)
        ag_txt = subprocess.check_output([ATTACK_GRAPH_BIN, "-l", "-p", "trace_output.P"])
        # logging.debug(ag_txt)
        return ag_txt

    def render(self):
        """
        Usage: render.sh [--arclabel]
                 [--reverse]
                 [--simple]
                 [-h|--help]

        :return:
        """
        my_env = os.environ.copy()
        # my_env["MULVAL_HOME"] = MULVALROOT
        my_env["MULVALROOT"] = MULVALROOT  # @TODO this is getting set to $MULVAL_HOME (literal) somewhere
        cmd = MULVALROOT + '/utils/render.sh'
        # subprocess.Popen(cmd, env=my_env, shell=True)
        # subprocess.call([MULVALROOT+'/utils/render.sh'], env=my_env, shell=True)
        subprocess.call('echo $MULVAL_HOME', env=my_env, shell=True)
        subprocess.call(cmd, env=my_env, shell=True)

class graph_gen(object):

    def __init__(self, *args, **kwargs):
        """
        Usage: graph_gen.sh [-r|--rule rulefile]
                    [-a|--additional additional_rulefile]
            [-c|--constraint constraint_file]
            [-g|--goal goal]
            [-d|--dynamic dynamic_file]
            [-p]
            [-s|--sat]
            [-t|--t trace_option]
            [-tr|--trim]
            [-v|--visualize [--arclabel] [--reverse]]
                    [--cvss]
                [-h|--help]
                [attack_graph_options]
                input_file

        :param args:
        :param kwargs:
        """
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
        _tracemode = TRACE_MODE if 'tracemode' not in kwargs else kwargs.get('tracemode')
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
        logging.info(pyxsb_query('cwd(D).'))



        # pyxsb_query('catch(abort,Exception,true).')

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
        # c2p_functor(b"consult", 1, reg_term(1))
        # c2p_string(b"environment", p2p_arg(reg_term(1), 1))
        # xsb_command()
        pyxsb_command('[environment].')


        # c2p_functor(b"tell", 1, reg_term(1))
        # c2p_string(b"goals.txt", p2p_arg(reg_term(1), 1))
        # xsb_command()
        pyxsb_command("tell('goals.txt').")

        pyxsb_command('writeln("Goal:"). ')

        # c2p_functor(b"iterate", 1, reg_term(1))
        # c2p_string(b"attackGoal(G),(write(' '), write_canonical(G), nl)", p2p_arg(reg_term(1), 1))
        # xsb_command()
        pyxsb_command("iterate(attackGoal(G),(write(' '), write_canonical(G), nl)).")
        pyxsb_command('told.')
        #     pyxsb_end_session()

        #     pyxsb_start_session(XSB_ARCH_DIR)
        # c2p_functor(b"consult", 1, reg_term(1))
        # c2p_string(b"run", p2p_arg(reg_term(1), 1))
        # xsb_command()
        pyxsb_command('[run].')

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


# def run_R_script(r_file_name, **opts):
#
#     if
#     subprocess.call('Rscript', r_file_name, env=my_env, shell=True)


# if __name__ == "__main__":
def Main():
    """
    Demo to run default MulVal input.P from python

    :return:
    """
    mulval_args, attackgraph_args = parseFlags()
    logging.debug('Parsed mulval args: %s' % mulval_args)
    logging.debug('Parsed attack graph args:logPath %s' % attackgraph_args)

    setup_test_dir()


    #####
    ## graph_gen.sh
    ####
    gg = graph_gen()
    gg.graph_gen()


    #####
    ## attack_graph.cpp
    ####
    ag = attack_graph()

    ag_text = ag.attack_graph().decode('UTF-8')
    # logging.debug(type(ag_text.decode('UTF-8')))
    gg.writeFile(WORKING_DIR + '/AttackGraph.txt', ag_text)

    verts = ''
    arcs  = ''
    for line in ag_text.splitlines():
        if re.search(r'AND|OR|LEAF', line):
            verts += line + '\n'
        else:
            arcs += line + '\n'

    # logging.info('arcs: %s' % arcs)
    # logging.info('verts: %s' % verts)

    gg.writeFile(WORKING_DIR + '/ARCS.CSV', arcs)
    gg.writeFile(WORKING_DIR + '/VERTICES.CSV', verts)

    ag.render()

    #####
    ## genTransMatrix
    ####
    inputDir = WORKING_DIR
    outfileName = os.path.splitext(INPUT_FILE_NAME)[0] # 'input'
    scriptsDir = DATA_DIR
    pathlib.Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)

    opts = dict()
    opts['scriptsDir'] = scriptsDir
    opts['inputDir'] = inputDir
    opts['outfileName'] = outfileName
    opts['PLOT_INTERMEDIATE_GRAPHS'] = True
    opts['MatrixFile'] = MATRIX_FILE

    # A = AttackGraph(inputDir=inputDir, scriptsDir=scriptsDir, opts=opts)
    A = AttackGraph(**opts)
    A.name = outfileName
    A.plot2(outfilename= A.name + '_001_orig.png')
    tmatrix = A.getTransMatrix(**opts)
    logging.debug('Created weighted transition matrix:\n %s' % tmatrix)

    # Run analytics

    mcsim_opts = dict()
    mcsim_opts['input'] = MATRIX_FILE
    mcsim_opts['output'] = RESULTS_DIR
    mcsim_opts['label'] = INPUT_BASE_NAME
    subprocess.call(['Rscript', DATA_DIR + '/mcsim.r', '--input=' + MATRIX_FILE, '--output=' + RESULTS_DIR, '--label=' + INPUT_BASE_NAME ])


