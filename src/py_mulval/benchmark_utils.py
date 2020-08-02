import os
import pathlib
# import networkx
# from networkx.readwrite import json_graph
# import json
import logging
import os
import pathlib
import re
import sys
import tempfile
import uuid

from absl import app


import py_mulval.py_mulval as mulval
from py_mulval.py_mulval import graph_gen
from py_mulval.mulval_fact_graph import FactGraph
from py_mulval import configs
from py_mulval import data
from py_mulval import flags
# from py_mulval import genTransMatrix
from py_mulval import attack_graph
# from py_mulval import py_mulval
from py_mulval import sample
# from py_mulval import mulpy
from py_mulval import vm_util

from py_mulval.metrics.ag_metrics import mttf
import py_mulval.metrics
import os
# import pathlib
# import networkx
# from networkx.readwrite import json_graph
# import json

import os
SEP = os.path.sep
import logging
import sys

from py_mulval import configs
from py_mulval import data
from py_mulval import flags
# from py_mulval import genTransMatrix
from py_mulval import attack_graph
# from py_mulval import mulpy
# from py_mulval import py_mulval
from py_mulval import sample
from py_mulval import vm_util


from py_mulval.attack_graph import AttackGraph
from py_mulval.mulval_fact_graph import FactGraph

import threading
mulval_run_lock = threading.Lock()

import py_mulval.metrics
FLAGS = flags.FLAGS

FLAGS = flags.FLAGS

DEFAULT_AG_NAME = "AttackGraph.dot"
DEFAULT_AG_MODEL_NAME = "input.P"
# DEFAULT_AG_MODEL_NAME = None
DEFAULT_FG_NAME = '.'.join(('mulval_facts','input', 'dot'))

def get_attack_graph():
  """ loads an attack graph with the current configs
  :return:
  """
  # input_models_dir = FLAGS.models_dir or data.ResourcePath(SEP.join(('boromir', FLAGS.secmet_model_size, FLAGS.secmet_model_type)))
  # # infileName = FLAGS.input_file or DEFAULT_AG_NAME
  # infileName = DEFAULT_AG_NAME
  # filename = SEP.join((input_models_dir, infileName))
  # ag = None

  ag = None
  if not checkPathExists(get_ag_dotfile_location()):
    """ no attack graph found, try and make one"""
    # _RunMulVal()
    prepareInPath()

  if checkPathExists(get_ag_dotfile_location()):
    ag = AttackGraph()
    # ag.load_score_dict(data.ResourcePath('scoreDict.yml'))
    ag.load_score_dict(SEP.join((data.ResourcePath('secmet'), attack_graph.SCORE_DICT)))
    ag.inputDir = get_input_models_dir()
    ag.outputDir = get_baseDir()
    ag.scriptsDir = data.ResourcePath('secmet')
    ag.load_dot_string(get_ag_dotfile_location())
    logging.info('loaded attack graph from model: {}'.format(get_ag_dotfile_location()))

  return ag

def get_fact_graph():
  # input_models_dir = FLAGS.models_dir or data.ResourcePath(SEP.join(('boromir', FLAGS.secmet_model_size, FLAGS.secmet_model_type)))
  # infileName = FLAGS.input_file or DEFAULT_FG_NAME
  # filename = SEP.join((input_models_dir, infileName))
  # fg = None
  # if pathlib.Path(filename).exists():
  #   fg = AttackGraph()
  #   fg.load_dot_string(filename)

  fg = None
  if not checkPathExists(get_fg_dotfile_location()):
    """ no fact graph found, try and make one"""
    if not checkPathExists(get_fg_jsonfile_location()):
      """ no facts json file found, try and make it"""
      _RunMulVal()
    if checkPathExists(get_fg_jsonfile_location()):
      """ if we have a json file now, load fg and write dot file"""
      fg = FactGraph()
      fg.load_json_file(get_fg_jsonfile_location())
      fg.write_dot_file(get_fg_dotfile_location())

  if not fg and checkPathExists(get_fg_dotfile_location()):
    fg = FactGraph()
    fg.load_dot_string(get_fg_dotfile_location())
  return fg

def get_input_models_dir():
  # use --models_dir if set, otherwise used canned models
  return FLAGS.models_dir or data.ResourcePath(SEP.join(('boromir', FLAGS.secmet_model_size, FLAGS.secmet_model_type)))

def get_infilename():
  """ Gets the current model being used (with extension)

  @TODO there are too many different flags / options to specify this, need to settle on one
  :return:
  """
  # input_file = FLAGS.input_file or DEFAULT_AG_MODEL_NAME
  input_file = FLAGS.input_file
  if not input_file:
    input_file = FLAGS.input_model_name
  if not input_file:
    input_file = DEFAULT_AG_MODEL_NAME
  return input_file

def get_basefilename():
  """ the base filename to construct related files from
  :return: #
  """
  return os.path.splitext(get_infilename())[0]

def get_baseDir():
  return vm_util.GetTempDir()

def checkPathExists(path):
  return pathlib.Path(path).exists()

def get_fg_dotfilename():
  return '.'.join(('mulval_facts' ,get_basefilename(), 'dot'))

def get_fg_dotfile_location():
  # return SEP.join((get_input_models_dir(), get_fg_dotfilename()))
  return SEP.join((get_baseDir(), get_fg_dotfilename()))

def get_fg_jsonfile_name():
  # return '.'.join(('mulval_facts', get_basefilename(), 'json'))
  return '.'.join(('mulval_facts',  'json'))

def get_fg_jsonfile_location():
  return str(SEP.join((get_baseDir(), get_fg_jsonfile_name())))

def get_ag_dotfilename():
  # return '.'.join((get_basefilename(), 'AttackGraph','dot'))
  return '.'.join(('AttackGraph', 'dot'))

def get_ag_dotfile_location():
  return SEP.join((get_baseDir(), get_ag_dotfilename()))

def get_ag_pfile_name():
  return '.'.join((get_basefilename(), 'P'))

def get_ag_pfile_source_location(): # the source file dont write here
  return str(SEP.join((get_input_models_dir(), get_ag_pfile_name())))

def get_ag_pfile_location(): # the local working  copy we can alter
  return str(SEP.join((get_baseDir(), get_ag_pfile_name())))

def prepareInPath():
  """ Prepares input path for the benchmark

    For all benchmarks, checks if fact graph exists and makes it if not
    For AG metrics, checks if the AttackGraph.dot exists and make it if not

        models_dir: /opt/projects/diss/py-mulval/data/models
        rules_dir: /opt/projects/diss/py-mulval/data/rules
        data_dir: /opt/projects/diss/py-mulval/data
        secmet_ag_path: AttackGraph.dot

        secmet_random_cvss_score: True
  :return: the prepared working directory
  """
  # use --models_dir if set, otherwise used canned models
  # input_models_dir = FLAGS.models_dir or data.ResourcePath(SEP.join(('boromir', FLAGS.secmet_model_size, FLAGS.secmet_model_type)))
  input_models_dir = get_input_models_dir()

  # infileName = FLAGS.input_file or DEFAULT_AG_MODEL_NAME
  infileName = get_infilename()

  # filename = os.path.splitext(infileName)[0] # the base filename to construct related files from
  filename = get_basefilename()

  ###
  # Setup Facts Graphs Here
  ###

  # explicit_fg_found = (FLAGS.secmet_fg_dot and pathlib.Path(FLAGS.secmet_fg_dot).exists()) # facts graph has been saved before, so use it
  # default_factsfile = input_models_dir + SEP + 'mulval_facts.' + filename
  # default_fg_found = pathlib.Path(default_factsfile + '.dot').exists() # facts for this model have been saved in the default destination
  # default_facts_json_found = pathlib.Path(default_factsfile + '.json').exists() # facts for this model have been created in the default destination
  # fg_dotfile_name = '.'.join(('mulval_facts' ,filename, 'dot'))
  # fg_dotfile_location = str(SEP.join((input_models_dir, fg_dotfile_name)))
  # fg_jsonfile_name = str('.'.join(('mulval_facts', filename, 'json')))
  # fg_jsonfile_location = str(SEP.join((get_baseDir(), fg_jsonfile_name)))


  explicit_fg_found = (FLAGS.secmet_fg_dot and checkPathExists(LAGS.secmet_fg_dot))
  fg_dotfile_location = get_fg_dotfile_location()
  default_fg_found = checkPathExists(fg_dotfile_location)  # facts for this model have been
  # saved in the default destination
  fg_jsonfile_location = get_fg_jsonfile_location()
  default_facts_json_found = checkPathExists(fg_jsonfile_location)  # facts for this model have been
  # created in the default destination


  fg_found = explicit_fg_found or default_fg_found
  if default_facts_json_found and not fg_found: # if we found json facts just make the dot now
    fg = FactsGraph()
    fg.load_json_file(fg_jsonfile_location)
    fg.name = filename
    fg.write_dot_file(fg_dotfile_location)  # make a new outfile for next time
    fg_found = True

  ###
  # Setup Attack Graph Here (if needed)
  ###
  # ag_dotfile_name = '.'.join((filename, 'AttackGraph','dot'))
  # ag_dotfile_location = SEP.join((input_models_dir, ag_dotfile_name))
  # ag_pfile_name = '.'.join((filename, 'P'))
  # ag_pfile_location = SEP.join((input_models_dir, ag_pfile_name))
  ag_dotfile_name = get_ag_dotfilename()
  ag_dotfile_location = get_ag_dotfile_location()
  ag_pfile_name = get_ag_pfile_name()
  ag_pfile_location = get_ag_pfile_location()

  # explicit_ag_found = (FLAGS.models_dir and pathlib.Path(FLAGS.models_dir + SEP + 'AttackGraph.dot').exists()) # attack graph has been saved before, so use it
  explicit_ag_found = (input_models_dir and infileName and pathlib.Path(
      ag_dotfile_location).exists())  # attack graph has
  # been saved before, so use it

  attack_model_found = checkPathExists(get_ag_pfile_source_location())

  if not explicit_ag_found and not attack_model_found:  # we don't have a graph or a model... maybe we don't need them
    logging.debug('no attack model found, lets test for outcomes sometime')

  if not explicit_ag_found and attack_model_found: #  create the ag.dot  here
    # if not get_baseDir(): # mulval running dir
    #   FLAGS['base_dir'].parse(get_baseDir())

    # write the model to our cwd
    src = get_ag_pfile_source_location()
    dst = get_ag_pfile_location()
    logging.error('Writing MulVal source model from {} to {} '.format(src, dst))
    copy_file(src, dst) # we're copying mulval.P file to working directory here

    # mulpy._RunMulVal() # this adds ag.dot to this dir, and should make fg.json if needed
    # mulval_opts = {'input_file': ag_pfile_location,
    #                }
    _RunMulVal(**get_mulval_graphgen_args())


    # # copy the ag.dot to original source for next time
    # # dst = SEP.join((input_models_dir, '.'.join(inputfile, 'AttackGraph','dot'))) # write ag to inputmodel.AttackGraph.dot for next time
    # dst = ag_dotfile_location
    # # src = SEP.join((get_baseDir(), 'AttackGraph.dot'))
    # copy_file(src, dst) # we're copying mulval run output to reference directory here
    attack_model_found = True # we should have a factgraph now

  if not fg_found and attack_model_found: # we never saved our facts.dot
    fg = FactGraph()
    fg.load_json_file(fg_jsonfile_location)
    fg.name = filename
    fg.write_dot_file(fg_dotfile_location)
    fg_found = True

  if not attack_model_found:
    logging.error('no attack model found at: {}'.format(get_ag_pfile_source_location()))
  if not explicit_ag_found:
    logging.error('no attack graph found at: {}'.format(ag_dotfile_location))
  if not fg_found:
    logging.error('no fact graph found at: {}'.format(fg_dotfile_location ))
  if not default_facts_json_found:
    logging.error('no json facts found at:  {}'.format(fg_jsonfile_location))

  return input_models_dir

def _RunMulVal(**mulval_args):

  args = get_mulval_graphgen_args()
  args.update(mulval_args)
  logging.info('running mulval with args: {}'.format(args))

  with mulval_run_lock:



    #####
    ## graph_gen.sh
    ####
    gg = mulval.graph_gen(**mulval_args)
    gg.graph_gen()
    gg.runMulVal()

    #####
    ## attack_graph.cpp
    ####
    ag_args = {}
    ag = mulval.attack_graph(**ag_args)

    ag_text = ag.attack_graph().decode('UTF-8')
    gg.writeFile(get_baseDir() + '/AttackGraph.txt', ag_text)

    verts = ''
    arcs = ''
    for line in ag_text.splitlines():
      if re.search(r'AND|OR|LEAF', line):
        verts += line + '\n'
      else:
        arcs += line + '\n'

    # logging.info('arcs: %s' % arcs)
    # logging.info('verts: %s' % verts)

    gg.writeFile(get_baseDir() + '/ARCS.CSV', arcs)
    #  print('------------writing ag---------', get_baseDir())
    gg.writeFile(get_baseDir() + '/VERTICES.CSV', verts)

    ag.render()


def copy_file(src, dst):
  """ Copies (with mods) input file to working dir
  :param src:
  :param dst:
  :return:
  """
  if pathlib.Path(src).exists():
    input_p = pathlib.Path(src).read_text()
  else:
    logging.error('no file found')
  #   input_p = """attackerLocated(internet).
  # attackGoal(execCode(workStation,_)).
  #
  # hacl(internet, webServer, tcp, 80).
  # hacl(webServer, _,  _, _).
  # hacl(fileServer, _, _, _).
  # hacl(workStation, _, _, _).
  # hacl(H,H,_,_).
  #
  # /* configuration information of fileServer */
  # networkServiceInfo(fileServer, mountd, rpc, 100005, root).
  # nfsExportInfo(fileServer, '/export', _anyAccess, workStation).
  # nfsExportInfo(fileServer, '/export', _anyAccess, webServer).
  # vulExists(fileServer, vulID, mountd).
  # vulProperty(vulID, remoteExploit, privEscalation).
  # localFileProtection(fileServer, root, _, _).
  #
  # /* configuration information of webServer */
  # vulExists(webServer, 'CAN-2002-0392', httpd).
  # vulProperty('CAN-2002-0392', remoteExploit, privEscalation).
  # networkServiceInfo(webServer , httpd, tcp , 80 , apache).
  #
  # /* configuration information of workStation */
  # nfsMounted(workStation, '/usr/local/share', fileServer, '/export', read).
  # """
  # write input file to working directory if it doesn't exist
  outfile = dst
  logging.debug(('creating input file: %s') % outfile)
  if not pathlib.Path(outfile).exists():
    with open(outfile, 'w+') as file:
      file.write(input_p)
    logging.debug(('creating input file: %s') % outfile)


def get_mulval_graphgen_args():
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
  #  """
  #
  # _MULVALROOT = MULVALROOT if 'MULVALROOT' not in kwargs else kwargs.get(
  #     'MULVALROOT')
  # self._type = None if 'type' not in kwargs else kwargs.get('type')  #
  # # 'run' | 'environment' includes the mulval_run line
  # self._tracemode = FLAGS.trace
  # self._dynamic_file = None
  # self._trim = False  # True is --trim | -tr flags passed
  # self._trim_rules = MULVALROOT + '/src/analyzer/advances_trim.P'
  # self._no_trim_rules = MULVALROOT + '/src/analyzer/advances_notrim.P'
  # self._cvss = False  # original script tests if this is zero (-z $CVSS) so
  # # this is probably a path not bool
  # self._goal = FLAGS.goal or None  # goal passed in a flag
  # self.rule_files = list()
  # self.rule_files_additional = list()
  # _input_file = self._input_file
  # _MULVALROOT = self._MULVALROOT
  # _type = self._type
  # _tracemode = self._tracemode
  # _dynamic_file = self._dynamic_file
  # _trim = self._trim
  # _trim_rules = self._trim_rules
  # _no_trim_rules = self._no_trim_rules
  # _cvss = self._cvss
  # _goal = self._goal

  # our flags
  # flags.DEFINE_multi_string('rule', None, 'add rule file(s).', short_name='r')
  # flags.DEFINE_multi_string('additional', None, 'add additional rule file(s).', short_name='a')
  # flags.DEFINE_multi_string('constraint', None, 'add constraint file(s).', short_name='c')
  # flags.DEFINE_multi_string('goal', None, 'add goal(s).', short_name='g')
  # flags.DEFINE_multi_string('dynamic', None, 'add dynamic file(s).', short_name='d')
  # flags.DEFINE_bool('visualize', True, 'create viz (implies csv output).', short_name='V')
  # flags.DEFINE_bool('write_csv', True, 'Write CSV output', short_name='l')
  # flags.DEFINE_string('input_file', None, 'input file', short_name='i')
  # flags.DEFINE_bool('arclabel', True, 'arclabel')
  # flags.DEFINE_bool('reverse', True, 'reverse')
  # flags.DEFINE_bool('simple', True, 'simple')
  # flags.DEFINE_bool('metric', False, 'metric')
  # flags.DEFINE_bool('sat', True, 'SAT', short_name='s')
  # flags.DEFINE_bool('satgui', True, 'SAT GUI', short_name='sg')
  # flags.DEFINE_string('trace', 'completeTrace2', 'trace option', short_name='t')
  # flags.DEFINE_bool('trim', True, 'trim', short_name='tr')
  # flags.DEFINE_bool('trimdom', True, 'trimdom', short_name='td')
  # flags.DEFINE_bool('cvss', True, 'cvss')
  # flags.DEFINE_bool('ma', True, 'metric artifacts')

  """ original codes flags
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

  mulval_args = {
      'input_file':            get_ag_pfile_location(),
      # 'MULVALROOT':            '/test/this/dir/out/mulval/mulval',
      # 'cvss':                  False,
      # 'dynamic_file':          None,
      # 'goal':                  None,
      # '_no_trim_rules':        '/test/this/dir/out//mulval/mulval/src/analyzer/advances_notrim.P',
      # 'tracemode':             'dummycompleteTrace2',
      # 'trim':                  False,
      # 'trim_rules':            '/dummy/mulval/mulval/src/analyzer/advances_trim.P',
      # 'type':                  None,
      # 'rule_files':            [],
      # 'rule_files_additional': [],
  }
  #  print(mulval_args)

  return mulval_args





