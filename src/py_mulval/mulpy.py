import logging
import os
import pathlib
import re
import sys
import tempfile
import uuid

from absl import app

from py_mulval import flag_util
from py_mulval import vm_util
from py_mulval import log_util
from py_mulval import publisher
from py_mulval import py_mulval
from py_mulval import sample
from py_mulval.benchmark_sets import *

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
# flags.DEFINE_string('helpmatch', None, 'help flag')
# flags.DEFINE_string('helpmatchmd', None, 'help markdown flag')

#####
# Mulpy Flags
#####
# flags.DEFINE_string('run_uri', None, 'Unique ID for this run.')
flags.DEFINE_string('base_dir', None, 'Working dir. Default: /tmp/<run_uri>/')
flags.DEFINE_string('data_dir', None, 'Directory to find scripts, ymls, etc.')
flags.DEFINE_string('models_dir', None, 'Prefix model files with this path.')
flags.DEFINE_string('rules_dir', None, 'Prefix rule files with this path.')
flags.DEFINE_string('output_dir', None, 'Prefix output files with this path.')


def _GetTempDir():
  return tempfile.gettempdir()


def _SetBaseDir():
  if not FLAGS.base_dir:
    FLAGS.base_dir = SEP.join((_GetTempDir(), 'mulpy', 'runs'))
  FLAGS.base_dir = SEP.join((FLAGS.base_dir, FLAGS.run_uri))
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


def writeFile(file_name, file_text, mode='w+'):
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
  FLAGS.run_uri = str(uuid.uuid4())[-8:]
  logging.info('Run ID initialized: {}'.format(FLAGS.run_uri))


def SetupMulpy():
  logging.info('Setting up Mulpy environment...')
  InitRunID()
  _SetBaseDir()
  # setup logging once we have a run_uri and base dir
  log_util.ConfigureLogging(logging.DEBUG,
                            SEP.join((FLAGS.base_dir, 'cat-dog.log')),
                            FLAGS.run_uri)
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
  gg.runMulVal()

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
  print('------------writing ag---------', FLAGS.base_dir)
  gg.writeFile(FLAGS.base_dir + '/VERTICES.CSV', verts)

  ag.render()

# def _GenTransMatrix():
#
#   #####
#   ## genTransMatrix
#   ####
#   inputDir = FLAGS.base_dir
#   outfileName = os.path.splitext(FLAGS.input_file)[0]  # 'input'
#   scriptsDir = FLAGS.data_dir
#   pathlib.Path(FLAGS.output_dir).mkdir(parents=True, exist_ok=True)
#
#   opts = dict()
#   opts['scriptsDir'] = scriptsDir
#   opts['inputDir'] = inputDir
#   opts['outfileName'] = outfileName
#   opts['PLOT_INTERMEDIATE_GRAPHS'] = True
#   matrix_file = SEP.join((FLAGS.output_dir, outfileName + '.csv'))
#   opts['MatrixFile'] = matrix_file
#
#   # A = AttackGraph(inputDir=inputDir, scriptsDir=scriptsDir, opts=opts
#   A = genTransMatrix.AttackGraph(**opts)
#   A.name = outfileName
#   A.plot2(outfilename=A.name + '_001_orig.png')
#   tmatrix = A.getTransMatrix(**opts)
#   logging.debug('Created weighted transition matrix:\n %s' % tmatrix)
#
#   # Run analytics
#
#   mcsim_opts = dict()
#   mcsim_opts['input'] = matrix_file
#   mcsim_opts['output'] = FLAGS.output_dir
#   mcsim_opts['label'] = outfileName
#   subprocess.call(['Rscript', FLAGS.data_dir + '/mcsim.r', '--input=' + matrix_file,
#                    '--output=' + FLAGS.output_dir, '--label=' + outfileName])


def PublishRunStartedSample():
  """Publishes a sample indicating that a run has started.

  This sample is published immediately so that there exists some metric for any
  run (even if the process dies).

  Args:
    spec: The BenchmarkSpec object with run information.
  """
  collector = publisher.SampleCollector()
  metadata = {
      'flags': str(flag_util.GetProvidedCommandLineFlags())
  }
  collector.AddSamples(
      [sample.Sample('Run Started', 1, 'Run Started', metadata)],
      FLAGS.run_uri, FLAGS.run_uri)
  collector.PublishSamples()


def _PrintHelp(matches=None):
  """Prints help for flags defined in matching modules.

  Args:
    matches: regex string or None. Filters help to only those whose name
      matched the regex. If None then all flags are printed.
  """
  if not matches:
    print(FLAGS)
  else:
    flags_by_module = FLAGS.flags_by_module_dict()
    modules = sorted(flags_by_module)
    regex = re.compile(matches)
    for module_name in modules:
      if regex.search(module_name):
        print(FLAGS.module_help(module_name))


def _PrintHelpMD(matches=None):
  """Prints markdown formatted help for flags defined in matching modules.

  Works just like --helpmatch.

  Args:
    matches: regex string or None. Filters help to only those whose name matched
      the regex. If None then all flags are printed.
  Eg:
  * all flags: `./pkb.py --helpmatchmd .*`  > testsuite_docs/all.md
  * linux benchmarks: `./pkb.py --helpmatchmd linux_benchmarks.*`  >
    testsuite_docs/linux_benchmarks.md  * specific modules `./pkb.py
    --helpmatchmd iperf`  > testsuite_docs/iperf.md  * windows packages
    `./pkb.py --helpmatchmd windows_packages.*`  >
    testsuite_docs/windows_packages.md
  * GCP provider: `./pkb.py --helpmatchmd providers.gcp.* >
    testsuite_docs/providers_gcp.md`
  """

  flags_by_module = FLAGS.flags_by_module_dict()
  modules = sorted(flags_by_module)
  regex = re.compile(matches)
  for module_name in modules:
    if regex.search(module_name):
      # Compile regex patterns.
      module_regex = re.compile(MODULE_REGEX)
      flags_regex = re.compile(FLAGS_REGEX, re.MULTILINE | re.DOTALL)
      flagname_regex = re.compile(FLAGNAME_REGEX, re.MULTILINE | re.DOTALL)
      docstring_regex = re.compile(DOCSTRING_REGEX, re.MULTILINE | re.DOTALL)
      # Retrieve the helpmatch text to format.
      helptext_raw = FLAGS.module_help(module_name)

      # Converts module name to github linkable string.
      # eg: perfkitbenchmarker.linux_benchmarks.iperf_vpn_benchmark ->
      # perfkitbenchmarker/linux_benchmarks/iperf_vpn_benchmark.py
      module = re.search(
          module_regex,
          helptext_raw,
      ).group(1)
      module_link = module.replace('.', '/') + '.py'
      # Put flag name in a markdown code block for visibility.
      flags = re.findall(flags_regex, helptext_raw)
      flags[:] = [flagname_regex.sub(r'`\1`\2', flag) for flag in flags]
      # Get the docstring for the module without importing everything into our
      # namespace. Probably a better way to do this
      docstring = 'No description available'
      # Only pull doststrings from inside pkb source files.
      if isfile(module_link):
        with open(module_link, 'r') as f:
          source = f.read()
          # Get the triple quoted matches.
          docstring_match = re.search(docstring_regex, source)
          # Some modules don't have docstrings.
          # eg perfkitbenchmarker/providers/alicloud/flags.py
          if docstring_match is not None:
            docstring = docstring_match.group(1)
      # Format output and print here.
      if isfile(module_link):  # Only print links for modules we can find.
        print('### [' + module, '](' + BASE_RELATIVE + module_link + ')\n')
      else:
        print('### ' + module + '\n')
      print('#### Description:\n\n' + docstring + '\n\n#### Flags:\n')
      print('\n'.join(flags) + '\n')

def Main():
  log_util.ConfigureBasicLogging()
  logging.info('Basic Logging configured.')
  _ParseFlags()
  # if FLAGS.helpmatch:
  #   _PrintHelp(FLAGS.helpmatch)
  #   return 0
  # if FLAGS.helpmatchmd:
  #   _PrintHelpMD(FLAGS.helpmatchmd)
  #   return 0
  SetupMulpy()
  # collector = publisher.SampleCollector()
  # PublishRunStartedSample()
  # os.chdir(FLAGS.base_dir)
  _RunMulVal()
  # _GenTransMatrix()


if __name__ == '__main__':
  app.run(Main)
