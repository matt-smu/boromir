
from absl import app
from absl import flags

from itertools import chain
from jinja2 import Template
import logging
import os
import pathlib
from pyxsb import *

# from py_mulval import log_util

FLAGS = flags.FLAGS

SEP = os.path.sep

# needed if pyxsb can't find xsb
XSB_ARCH_DIR = '/opt/apps/xsb/XSB/config/x86_64-unknown-linux-gnu'

## port MulVals graph_gen.sh to python

# MulVal Install Files
MULVALROOT = '/opt/mulval'
MULVALROOT = '/opt/projects/diss/mulval/mulval'
INTERACTIONRULES = SEP.join((MULVALROOT, 'kb/interaction_rules.P'))
INTERACTIONRULES_CVSS = SEP.join(
    (MULVALROOT, 'kb/interaction_rules_with_metrics.P'))
RULES_WITH_METRIC_ARTIFACTS = SEP.join(
    (MULVALROOT, 'kb/interaction_rules_with_metric_artifacts.P'))
ATTACK_GRAPH_BIN = SEP.join((MULVALROOT, "bin/attack_graph"))

RUNNING_RULES_NAME = 'running_rules.P'
ENV_FILE_NAME = 'environment.P'
RUN_FILE_NAME = 'run.P'

#####
# MulVal Flags
#####
flags.DEFINE_multi_string('rule', None, 'add rule file(s).', short_name='r')
flags.DEFINE_multi_string('additional', None, 'add additional rule file(s).',
                          short_name='a')
flags.DEFINE_multi_string('constraint', None, 'add constraint file(s).',
                          short_name='c')
flags.DEFINE_multi_string('goal', None, 'add goal(s).', short_name='g')
flags.DEFINE_multi_string('dynamic', None, 'add dynamic file(s).',
                          short_name='d')
flags.DEFINE_bool('visualize', True, 'create viz (implies csv output).',
                  short_name='V')
flags.DEFINE_bool('write_csv', True, 'Write CSV output', short_name='l')
flags.DEFINE_string('input_file', None, 'input file', short_name='i')
flags.DEFINE_bool('arclabel', True, 'arclabel')
flags.DEFINE_bool('reverse', True, 'reverse')
flags.DEFINE_bool('simple', True, 'simple')
flags.DEFINE_bool('metric', False, 'metric')
flags.DEFINE_bool('sat', True, 'SAT', short_name='s')
flags.DEFINE_bool('satgui', True, 'SAT GUI', short_name='sg')
flags.DEFINE_string('trace', 'completeTrace2', 'trace option', short_name='t')
flags.DEFINE_bool('trim', True, 'trim', short_name='tr')
flags.DEFINE_bool('trimdom', True, 'trimdom', short_name='td')
flags.DEFINE_bool('cvss', True, 'cvss')
flags.DEFINE_bool('ma', True, 'metric artifacts')

"""
Mulval facts for queries
"""
# primitives
# primitive(inCompetent(_principal)).
# primitive(competent(_principal)).
# primitive(clientProgram(_host, _programname)).
# primitive(vulExists(_host, _vulID, _program)).
# primitive(vulProperty(_vulID, _range, _consequence)).
# primitive(hacl(_src, _dst, _prot, _port)).
# primitive(attackerLocated(_host)).
# primitive(hasAccount(_principal, _host, _account)).
# primitive(networkServiceInfo(_host, _program, _protocol, _port, _user)).
# primitive(setuidProgramInfo(_host, _program, _owner)).
# primitive(nfsExportInfo(_server, _path, _access, _client)).
# primitive(nfsMounted(_client, _clientpath, _server, _serverpath, _access)).
# primitive(localFileProtection(_host, _user, _access, _path)).
# primitive(dependsOn(_h, _program, _library)).
# primitive(installed(_h, _program)).
# primitive(bugHyp(_,_,_,_)).
# primitive(vulExists(_machine,_vulID,_program,_range,_consequence)).
# primitive(canAccessFile(_host, _user, _access, _path)).
# primitive(isWebServer(_host)).
# meta(cvss(_vulID, _ac)).
inCompetent = 'inCompetent(A)'
competent = 'competent(A) '
clientProgram = 'clientProgram(A, B,)'
vulExists = 'vulExists(A, B, C)'
vulProperty = 'vulProperty(A, B, C)'
hacl = 'hacl(A, B, C, D)'
attackerLocated = 'attackerLocated(A)'
hasAccount = 'hasAccount(A, B, C)'
networkServiceInfo = 'networkServiceInfo(A, B, C, D, E)'
setuidProgramInfo = 'setuidProgramInfo(A, B, C)'
nfsExportInfo = 'nfsExportInfo(A, B, C, D)'
nfsMounted = 'nfsMounted(A, B, C, D, E)'
localFileProtection = 'localFileProtection(A, B, C, D)'
dependsOn = 'dependsOn(A, B, C)'
installed = 'installed(A, B)'
bugHyp = 'bugHyp(A, B, C)'
vulExists = 'vulExists(A, B, C, D, E)'
canAccessFile = 'canAccessFile(A, B, C, D)'
isWebServer = 'isWebServer(A)'
# cvss = 'cvss(A, B,)'
primitive = [inCompetent, competent, clientProgram, vulExists, vulProperty,
             hacl, attackerLocated, hasAccount, networkServiceInfo,
             setuidProgramInfo, nfsExportInfo, nfsMounted, localFileProtection,
             dependsOn, installed, bugHyp, vulExists, canAccessFile,
             isWebServer,]

# derived
# execCode/2.
# netAccess/3.
# canAccessHost/1.
# canAccessFile/4.
# accessFile/3.
# principalCompromised/1.
# vulExists/5.
# logInService/3.
execCode = 'execCode(A,B)'
netaccess = 'netAccess(A,B,C)'
canAccessHost = 'canAccessHost(A)'
canAccessFile = 'canAccessFile(A,B,C,D)'
accessFile = 'accessFile(A,B,C)'
accessMaliciousInput = 'accessMaliciousInput(A,B,C)'
principalCompromised = 'principalCompromised(A)'
dos = 'dos(A)'
vulExists = 'vulExists(A,B,C,D,E)'
logInService = 'logInService(A,B,C)'
advances = 'advances(A,B)'
# attackGoal = 'attackGoal(A)'
derived = [execCode, netaccess, canAccessHost, canAccessFile, dos, accessFile,
           accessMaliciousInput, principalCompromised, vulExists, logInService,
           advances, ]


# print(x)

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
    # subprocess.run([ATTACK_GRAPH_BIN, "trace_output.P"],
    # stdout=subprocess.PIPE)
    # subprocess.run([ATTACK_GRAPH_BIN,"-l", "trace_output.P", ">",
    # './AttackGraph.txt'], shell=True)
    ag_txt = subprocess.check_output(
        [ATTACK_GRAPH_BIN, "-l", "-p", "trace_output.P"])
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
    # @TODO this is getting set to $MULVAL_HOME (literal) somewhere
    my_env["MULVALROOT"] = MULVALROOT
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
    self._input_file = FLAGS.input_file # not sure where this came from next line
    # self._input_file = INPUT_FILE if 'input_file' not in kwargs else kwargs.get(
    #     'input_file')
    # self._rule_files = FLAGS.rule  # kwargs.get('rulefile')
    # self.
    self._MULVALROOT = MULVALROOT if 'MULVALROOT' not in kwargs else kwargs.get(
      'MULVALROOT')
    self._type = None if 'type' not in kwargs else kwargs.get('type')  #
    # 'run' | 'environment' includes the mulval_run line
    self._tracemode = FLAGS.trace
    self._dynamic_file = None
    self._trim = False  # True is --trim | -tr flags passed
    self._trim_rules = MULVALROOT + '/src/analyzer/advances_trim.P'
    self._no_trim_rules = MULVALROOT + '/src/analyzer/advances_notrim.P'
    self._cvss = False  # original script tests if this is zero (-z $CVSS) so
    # this is probably a path not bool
    self._goal = FLAGS.goal or None  # goal passed in a flag
    self.rule_files = list()
    self.rule_files_additional= list()
    # template this out for later
    # vars:
    self.ts = """:-['{{ _MULVALROOT }}/lib/libmulval'].  % start base run script
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

  def graph_gen(self, *args, **kwargs):
    """
`    do the things graph_gen.sh does
    this should leave a trace_output.P
    file in cwd that gets sent to attack_graph.cpp`
    """

    _input_file = self._input_file
    _MULVALROOT = self._MULVALROOT
    _type = self._type
    _tracemode = self._tracemode
    _dynamic_file = self._dynamic_file
    _trim = self._trim
    _trim_rules = self._trim_rules
    _no_trim_rules = self._no_trim_rules
    _cvss = self._cvss
    _goal = self._goal

    logging.info('writing rule files to working directory %s...' % FLAGS.base_dir)
    self.rule_files.append(INTERACTIONRULES)  # @TODO cvss and ma checks
    # append RULES_DIR to rule files path... @TODO expect full path for each?
    rulefiles = list((SEP.join((FLAGS.rules_dir, file)) for file in FLAGS.rule)) if FLAGS.rule else None
    # if rulefiles:
    logging.debug('rulefiles to write from: %s ' % list(rulefiles))
    self.rule_files.append(*rulefiles)
    logging.debug('rule files: %s' % self.rule_files)
    logging.debug('additional rule files: %s' % self.rule_files_additional)
    self.writeRulesFile(self.rule_files, self.rule_files_additional)

    logging.info('writing environment file %s...' % SEP.join((FLAGS.base_dir, ENV_FILE_NAME)))
    tm = Template(self.ts)
    logging.debug('locals: %s' % locals())
    self.writeFile(SEP.join((FLAGS.base_dir, ENV_FILE_NAME)), tm.render(locals()))

    logging.info('writing run file %s...' % SEP.join((FLAGS.base_dir, RUN_FILE_NAME)))
    self.writeFile(SEP.join((FLAGS.base_dir, RUN_FILE_NAME)), tm.render(locals(), _type='run'))

    logging.info('running mulval in xsb...')
    os.chdir(FLAGS.base_dir)
    # self.runMulVal()

  def writeRulesFile(self, _RULE_FILES, _RULE_FILES_ADDITIONAL):
    """@TODO needs logic for placement, tabling, validation"""

    with open(SEP.join((FLAGS.base_dir,RUNNING_RULES_NAME)), 'w+') as outfile:
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

  def queryMulValFacts(self):
    """Gets all facts for the current xsb session
    """
    import binascii
    allfacts = {}

    def parseRow(row):
      results = []
      for item in row:
        if type(item) == XSBAtom:
          results.append(item.name)
        elif type(item) == XSBVariable:
          results.append(('var', str(binascii.hexlify(bytes(item.name, 'utf-8')))))
        else:
          results.append(item)
      return results

    for q in primitive:
      name = q[:q.index("(")]
      rows = pyxsb_query('{}.'.format(q))
      #     print('------{}-------'.format(name))
      result = []
      for row in rows:
        items = parseRow(row)
        result.append(items)
      if name not in allfacts.keys():
        allfacts[name] = []
      allfacts[name].append(result)

    for q in derived:
      name = q[:q.index("(")]
      rows = pyxsb_query('{}.'.format(q))
      #     print('------{}-------'.format(name))
      result = []
      for row in rows:
        print(row)
        items = parseRow(row)
        result.append(items)
      if name not in allfacts.keys():
        allfacts[name] = []
      if allfacts[name] is not None:
        allfacts[name].append(result)

    return allfacts

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
    # c2p_string(b"attackGoal(G),(write(' '), write_canonical(G), nl)",
    # p2p_arg(reg_term(1), 1))
    # xsb_command()
    pyxsb_command(
      "iterate(attackGoal(G),(write(' '), write_canonical(G), nl)).")
    pyxsb_command('told.')
    #     pyxsb_end_session()

    #     pyxsb_start_session(XSB_ARCH_DIR)
    # c2p_functor(b"consult", 1, reg_term(1))
    # c2p_string(b"run", p2p_arg(reg_term(1), 1))
    # xsb_command()
    pyxsb_command('[run].')

    # dump facts to file before exit
    facts_dict = self.queryMulValFacts()
    factfile = SEP.join((FLAGS.base_dir,'mulval_facts.json'))

    logging.debug('writing facts file to {}...'.format(factfile))
    with open(factfile, 'w') as file:
      json.dump(facts_dict, file)

    pyxsb_end_session()

