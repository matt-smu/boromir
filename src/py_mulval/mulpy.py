from absl import app
from absl import flags
import logging
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import uuid

from py_mulval import genTransMatrix
from py_mulval import log_util
from py_mulval import py_mulval

FLAGS = flags.FLAGS

SEP = os.path.sep

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
"""
# #####
# # MulVal Flags
# #####
# flags.DEFINE_multi_string('rule', None, 'add rule file(s).', short_name='r')
# flags.DEFINE_multi_string('additional', None, 'add additional rule file(s).',
#                           short_name='a')
# flags.DEFINE_multi_string('constraint', None, 'add constraint file(s).',
#                           short_name='c')
# flags.DEFINE_multi_string('goal', None, 'add goal(s).', short_name='g')
# flags.DEFINE_multi_string('dynamic', None, 'add dynamic file(s).',
#                           short_name='d')
# flags.DEFINE_bool('visualize', True, 'create viz (implies csv output).',
#                   short_name='V')
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

#####
# Mulpy Flags
#####
flags.DEFINE_string('run_id', None, 'Unique ID for this run.')
flags.DEFINE_string('base_dir', None, 'Working dir. Default: /tmp/<run_id>/')
flags.DEFINE_string('data_dir', None, 'Directory to find scripts, ymls, etc.')
flags.DEFINE_string('models_dir', None, 'Prefix model files with this path.')
flags.DEFINE_string('rules_dir', None, 'Prefix rule files with this path.')
flags.DEFINE_string('output_dir', None, 'Prefix output files with this path.')


def _GetTempDir():
  return tempfile.gettempdir()


def _SetBaseDir():
  if not FLAGS.base_dir:
    FLAGS.base_dir = SEP.join((_GetTempDir(), 'mulpy'))
  FLAGS.base_dir = SEP.join((FLAGS.base_dir, FLAGS.run_id))
  logging.info('Base directory set to: {}'.format(FLAGS.base_dir))
  if not pathlib.Path(FLAGS.base_dir).exists():
    pathlib.Path(FLAGS.base_dir).mkdir(parents=True, exist_ok=True)


def _SetModelsDir():
  if not FLAGS.models_dir:
    FLAGS.models_dir = SEP.join((FLAGS.base_dir, 'models'))
  logging.info('Models directory set to: {}'.format(FLAGS.models_dir))
  if not pathlib.Path(FLAGS.models_dir).exists():
    pathlib.Path(FLAGS.models_dir).mkdir(parents=True, exist_ok=True)

def _SetOutputDir():
  if not FLAGS.output_dir:
    FLAGS.output_dir = SEP.join((FLAGS.base_dir, 'output'))
  logging.info('Output directory set to: {}'.format(FLAGS.output_dir))
  if not pathlib.Path(FLAGS.output_dir).exists():
    pathlib.Path(FLAGS.output_dir).mkdir(parents=True, exist_ok=True)

#
# def _SetRulesDir():
#   if not FLAGS.rules_dir:
#     FLAGS.models_dir = SEP.join((FLAGS.base_dir, 'models'))
#   logging.info('Models directory set to: {}'.format(FLAGS.models_dir))
#   if not pathlib.Path(FLAGS.models_dir).exists():
#     pathlib.Path(FLAGS.models_dir).mkdir(parents=True, exist_ok=True)


def writeFile(self, file_name, file_text, mode='w+'):
  """
  w  write mode
  r  read mode
  a  append mode
  w+  create file if it doesn't exist and open it in (over)write mode
      [it overwrites the file if it already exists]
  r+  open an existing file in read+write mode
  a+  create file if it doesn't exist and open it in append mode
  """
  with open(file_name, mode) as file:
    file.write(file_text)


def _ParseFlags(argv=sys.argv):
  """Parses the command-line flags."""
  try:
    argv = FLAGS(argv)
    logging.debug('Parsed command line flags: {}'.format(FLAGS.input_file))
  except flags.Error as e:
    logging.error(e)
    sys.exit(1)


def InitRunID():
  FLAGS.run_id = str(uuid.uuid4())[-8:]
  logging.info('Run ID initialized: {}'.format(FLAGS.run_id))


def SetupMulpy():
  logging.info('Setting up Mulpy environment...')
  InitRunID()
  _SetBaseDir()
  # setup logging once we have a run_id and base dir
  log_util.ConfigureLogging(logging.DEBUG,
                            SEP.join((FLAGS.base_dir, 'cat-dog.log')),
                            FLAGS.run_id)
  # try to get cli into main log... not always trustworthy
  logging.info('running command line: %s' % ' '.join(sys.argv))
  _SetModelsDir()
  # _SetRulesDir() # if no rules_dir just use default set
  _SetOutputDir()
  # Copy model or example into base_dir
  if pathlib.Path(SEP.join((FLAGS.models_dir, FLAGS.input_file))).exists():
    input_p = pathlib.Path(
      SEP.join((FLAGS.models_dir, FLAGS.input_file))).read_text()
  else:
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
  # write input file to working directory if it doesn't exist
  outfile = SEP.join((FLAGS.base_dir, FLAGS.input_file))
  logging.debug(('creating input file: %s') % outfile)
  if not pathlib.Path(outfile).exists():
    with open(outfile, 'w+') as file:
      file.write(input_p)
    logging.debug(('creating input file: %s') % outfile)

def _RunMulVal():

  mulval_args = {}
  if FLAGS.input_file and FLAGS.models_dir:
    mulval_args['input_file'] = SEP.join((FLAGS.models_dir, FLAGS.input_file))
  if not FLAGS.input_file and FLAGS.models_dir:
    pass # @TODO handle all models in dir


  #####
  ## graph_gen.sh
  ####
  gg = py_mulval.graph_gen(**mulval_args)
  gg.graph_gen()

  #####
  ## attack_graph.cpp
  ####
  ag_args = {}
  ag = py_mulval.attack_graph(**ag_args)

  ag_text = ag.attack_graph().decode('UTF-8')
  gg.writeFile(FLAGS.base_dir + '/AttackGraph.txt', ag_text)

  verts = ''
  arcs = ''
  for line in ag_text.splitlines():
    if re.search(r'AND|OR|LEAF', line):
      verts += line + '\n'
    else:
      arcs += line + '\n'

  # logging.info('arcs: %s' % arcs)
  # logging.info('verts: %s' % verts)

  gg.writeFile(FLAGS.base_dir + '/ARCS.CSV', arcs)
  gg.writeFile(FLAGS.base_dir + '/VERTICES.CSV', verts)

  ag.render()

def _GenTransMatrix():

  #####
  ## genTransMatrix
  ####
  inputDir = FLAGS.base_dir
  outfileName = os.path.splitext(FLAGS.input_file)[0]  # 'input'
  scriptsDir = FLAGS.data_dir
  pathlib.Path(FLAGS.output_dir).mkdir(parents=True, exist_ok=True)

  opts = dict()
  opts['scriptsDir'] = scriptsDir
  opts['inputDir'] = inputDir
  opts['outfileName'] = outfileName
  opts['PLOT_INTERMEDIATE_GRAPHS'] = True
  matrix_file = SEP.join((FLAGS.output_dir, outfileName + '.csv'))
  opts['MatrixFile'] = matrix_file

  # A = AttackGraph(inputDir=inputDir, scriptsDir=scriptsDir, opts=opts
  A = genTransMatrix.AttackGraph(**opts)
  A.name = outfileName
  A.plot2(outfilename=A.name + '_001_orig.png')
  tmatrix = A.getTransMatrix(**opts)
  logging.debug('Created weighted transition matrix:\n %s' % tmatrix)

  # Run analytics

  mcsim_opts = dict()
  mcsim_opts['input'] = matrix_file
  mcsim_opts['output'] = FLAGS.output_dir
  mcsim_opts['label'] = outfileName
  subprocess.call(['Rscript', FLAGS.data_dir + '/mcsim.r', '--input=' + matrix_file,
                   '--output=' + FLAGS.output_dir, '--label=' + outfileName])



def Main():
  log_util.ConfigureBasicLogging()
  logging.info('Basic Logging configured.')
  _ParseFlags()
  SetupMulpy()
  # os.chdir(FLAGS.base_dir)
  _RunMulVal()
  _GenTransMatrix()


if __name__ == '__main__':
  app.run(Main)
