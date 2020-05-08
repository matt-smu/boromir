# from unittest import TestCase
from pprint import pprint

"""Tests for py_mulval.attack_graph."""
from absl.testing import flagsaver
import os

SEP = os.path.sep
import py_mulval.boromir
# from py_mulval import genTransMatrix
# from py_mulval import mulpy

from py_mulval import benchmark_spec
from py_mulval import configs
from py_mulval import context
from py_mulval import flags
# from py_mulval import linux_benchmarks
from py_mulval import secmet_benchmarks
# from py_mulval import pkb  # pylint: disable=unused-import # noqa
# from py_mulval import static_virtual_machine as static_vm
from py_mulval.configs import benchmark_config_spec
from tests import common_test_case

# import tests.common_test_case


# flags.DEFINE_integer('benchmark_spec_test_flag', 0, 'benchmark_spec_test flag.')

FLAGS = flags.FLAGS

# import unittest
# from unittest import TestCase

from py_mulval import flags
from py_mulval import py_mulval

import sys

# py_mulval_path = r'/opt/projects/diss/py-mulval/src'
# sys.path.append(py_mulval_path)

FLAGS = flags.FLAGS
FLAGS.mark_as_parsed()

NAME = 'metf_ml'
UID = '1234abcd'

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


class _PyMulvalTestCase(common_test_case.CommonTestCase):
  # @flagsaver.flagsaver(use_vpn=True, vpn_service_gateway_count=1)
  def setUp(self):
    super(_PyMulvalTestCase, self).setUp()

    if not sys.warnoptions:  # https://bugs.python.org/issue33154
      import warnings
      warnings.simplefilter("ignore", (ResourceWarning, DeprecationWarning))
    self.addCleanup(context.SetThreadBenchmarkSpec, None)

  def _CreateBenchmarkSpecFromYaml(self, yaml_string, benchmark_name=NAME):
    config = configs.LoadConfig(yaml_string, {}, benchmark_name)
    return self._CreateBenchmarkSpecFromConfigDict(config, benchmark_name)

  def _CreateBenchmarkSpecFromConfigDict(self, config_dict, benchmark_name):
    config_spec = benchmark_config_spec.BenchmarkConfigSpec(benchmark_name, flag_values=FLAGS, **config_dict)
    benchmark_module = next((b for b in secmet_benchmarks.BENCHMARKS if b.BENCHMARK_NAME == benchmark_name))
    return benchmark_spec.BenchmarkSpec(benchmark_module, config_spec, UID)


class TestGraph_gen(_PyMulvalTestCase):

  def test_graph_gen_defaults(self):
    # gg = py_mulval.graph_gen(**mulval_args)
    gg = py_mulval.graph_gen()  # ** no args
    ignored_keys = ['ts']
    print('graphgen default values')
    for k, v in gg.__dict__.items():
      if k not in ignored_keys:
        pprint('{} :  {}'.format(k, v))

    self.assertEqual(gg._input_file, 'input.P')

  @flagsaver.flagsaver(run_uri='12flagsdummuy345678', secmet_random_seed='123flagsdummuy45',
                       base_dir='flagsdummuy/basedir', input_file='flagsdummuy.P',
                       models_dir='flagsdummuy/diss/py-mulval/data/models', secmet_model_type='flagsdummuy',
                       secmet_model_size='flagsdummuy',
                       rules_dir='/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/rules/archive',
                       rule=['arp_spoof.P', 'rules_sedap_hijack.P'])
  def test_graph_gen_from_flags(self):

    # gg = py_mulval.graph_gen(**mulval_args)
    gg = py_mulval.graph_gen()  # ** no args
    print('graphgen flags only values')
    ignored_keys = ['ts']
    for k, v in gg.__dict__.items():
      if k not in ignored_keys:
        pprint('{} :  {}'.format(k, v))

    self.assertEqual(gg._input_file, FLAGS.input_file)
    self.assertEqual(gg.rulefiles_basedir, FLAGS.rules_dir)

    rules = ['/opt/projects/diss/mulval/mulval/kb/interaction_rules.P',
     '/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/rules/archive/rules_sedap_hijack.P',
     '/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/rules/archive/arp_spoof.P']

    self.assertItemsEqual(gg.rule_files, rules)

    keys = ['_input_file', '_MULVALROOT', '_type', '_tracemode', '_dynamic_file', '_trim', '_trim_rules',
            '_no_trim_rules', '_cvss', '_goal', 'rule_files', 'rule_files_additional', 'ts']

  def test_graph_gen_from_args(self):
    mulval_args = {
        'input_file':            'single_host_12345.P',
        'MULVALROOT':            '/test/this/dir/out/mulval/mulval',
        'cvss':                  False,
        'dynamic_file':          None,
        'goal':                  None,
        '_no_trim_rules':        '/test/this/dir/out//mulval/mulval/src/analyzer/advances_notrim.P',
        'tracemode':             'dummycompleteTrace2',
        'trim':                  False,
        'trim_rules':            '/dummy/mulval/mulval/src/analyzer/advances_trim.P',
        'type':                  None,
        'rule_files':            ['local_exploit_rules.P'],
        'rule_files_additional': [], }

    # print(mulval_args.keys())
    gg = py_mulval.graph_gen(**mulval_args)
    print('graphgen args values')
    ignored_keys = ['ts']
    for k, v in gg.__dict__.items():
      if k not in ignored_keys:
        pprint('{} :  {}'.format(k, v))

    self.assertEqual(gg._input_file, mulval_args['input_file'])

    rules =  ['/opt/projects/diss/mulval/mulval/kb/interaction_rules.P',
     '/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/rules/local_exploit_rules.P']
    self.assertItemsEqual(gg.rule_files, rules)

  @flagsaver.flagsaver(run_uri='12flagsdummuy345678', secmet_random_seed='123flagsdummuy45',
                       base_dir='flagsdummuy/basedir', input_file='flagsdummuy.P',
                       models_dir='flagsdummuy/diss/py-mulval/data/models', secmet_model_type='flagsdummuy',
                       secmet_model_size='flagsdummuy',
                       rules_dir='/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/rules/archive',
                       rule=['arp_spoof.P', 'rules_sedap_hijack.P'])
  def test_graph_gen_from_flags_and_args(self):

    mulval_args = {
        'input_file':            'single_host_12345.P',
        'MULVALROOT':            '/test/this/dir/out/mulval/mulval',
        'cvss':                  False,
        'dynamic_file':          None,
        'goal':                  None,
        '_no_trim_rules':        '/test/this/dir/out//mulval/mulval/src/analyzer/advances_notrim.P',
        'tracemode':             'dummycompleteTrace2',
        'trim':                  False,
        'trim_rules':            '/dummy/mulval/mulval/src/analyzer/advances_trim.P',
        'type':                  None,
        'rule_files':            ['local_exploit_rules.P'],
        'rule_files_additional': [],
        'rule_files_base_dir':    ''}

    ## rule paths need work... just full uri? @TODO
    # self.rulefiles_basedir = FLAGS.rules_dir or data.ResourcePath('secmet/rules')
    # rules_args_only = ['/opt/projects/diss/mulval/mulval/kb/interaction_rules.P',
    #          '/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/rules/local_exploit_rules.P']
    rules_args_only = ['/opt/projects/diss/mulval/mulval/kb/interaction_rules.P',
                       '/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/rules/archive/local_exploit_rules.P']
    rules_flags_only = ['/opt/projects/diss/mulval/mulval/kb/interaction_rules.P',
             '/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/rules/archive/rules_sedap_hijack.P',
             '/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/rules/archive/arp_spoof.P']
    rules_all = list(set(rules_args_only) | set(rules_flags_only))

    # print(mulval_args.keys())
    gg = py_mulval.graph_gen(**mulval_args)
    print('graphgen flags and args final values')
    ignored_keys = ['ts']
    for k, v in gg.__dict__.items():
      if k not in ignored_keys:
        pprint('{} :  {}'.format(k, v))

    # gg = py_mulval.graph_gen(**mulval_args)

    self.assertEqual(gg._input_file, mulval_args['input_file'])
    self.assertItemsEqual(gg.rule_files, rules_all)

    keys = ['_input_file', '_MULVALROOT', '_type', '_tracemode', '_dynamic_file', '_trim', '_trim_rules',
            '_no_trim_rules', '_cvss', '_goal', 'rule_files', 'rule_files_additional', 'ts']

  def test_writeRulesFile(self):
    pass

  def test_writeFile(self):
    pass

  def test_runMulVal(self):
    pass


class Testattack_graph(_PyMulvalTestCase):
  def test_attack_graph(self):
    pass
