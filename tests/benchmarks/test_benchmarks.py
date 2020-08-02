
"""Tests for py_mulval.attack_graph."""
import sys

from mock import patch

from py_mulval import benchmark_sets
from py_mulval import secmet_benchmarks
from py_mulval import benchmark_spec
from py_mulval import context
from py_mulval import benchmark_sets
# from py_mulval import pkb  # pylint: disable=unused-import # noqa
# from py_mulval import static_virtual_machine as static_vm
from py_mulval.configs import benchmark_config_spec
# from py_mulval.linux_benchmarks import iperf_benchmark
# from py_mulval.providers.gcp import util
from tests import common_test_case

import unittest
import mock

from py_mulval import configs


# import tests.common_test_case
from py_mulval import flags
FLAGS = flags.FLAGS

flags.DEFINE_integer('benchmark_spec_test_flag', 0, 'benchmark_spec_test flag.')



_rule = 'local_exploit_rules.P'
_input_file = 'single_host_1.P'
_models_dir= '/opt/projects/diss/py-mulval/data/models'
_rules_dir = '/opt/projects/diss/py-mulval/data/rules '
_data_dir = '/opt/projects/diss/py-mulval/data'
_secmet_ag_path = 'AttackGraph.dot'


NAME = 'metf_ml'
UID = '1234abcd'

__default_config = """
default:
  description: Run  metric
  flags:
    input_file: single_host_1.P
    rule: local_exploit_rules.P
    models_dir: /opt/projects/diss/py-mulval/data/models 
    rules_dir: /opt/projects/diss/py-mulval/data/rules 
    data_dir: /opt/projects/diss/py-mulval/data
    secmet_ag_path: AttackGraph.dot
    # output_dir:   
  # vm_groups:
"""


METFML_CONFIG = """
metf_ml:
  description: Run metf metric
  flags:
    input_file: single_host_1.P
    rule: local_exploit_rules.P
    models_dir: /opt/projects/diss/py-mulval/data/models 
    rules_dir: /opt/projects/diss/py-mulval/data/rules 
    data_dir: /opt/projects/diss/py-mulval/data
    secmet_ag_path: AttackGraph.dot
    # output_dir: 
  # vm_groups:
"""

MTTF_CONFIG = """
mttf:
  description: Run mttf metric
  flags:
    input_file: single_host_1.P
    rule: local_exploit_rules.P
    models_dir: /opt/projects/diss/py-mulval/data/models
    secmet_fg_path: /opt/projects/diss/py-mulval/data/facts
    secmet_fg_name: mulval_facts.single_host_1.json
    rules_dir: /opt/projects/diss/py-mulval/data/rules
    data_dir: /opt/projects/diss/py-mulval/data
    secmet_ag_path: AttackGraph.dot
    # output_dir: 
    # vm_groups:
"""

class _BenchmarkTestCase(common_test_case.CommonTestCase):
  # @flagsaver.flagsaver(use_vpn=True, vpn_service_gateway_count=1)
  def setUp(self):
    super(_BenchmarkTestCase, self).setUp()

    if not sys.warnoptions:  # https://bugs.python.org/issue33154
      import warnings
      warnings.simplefilter("ignore", (ResourceWarning, DeprecationWarning))
    self.addCleanup(context.SetThreadBenchmarkSpec, None)

    # create set of valid benchmark names from the benchmark directory
    self.valid_benchmark_names = set()
    for benchmark_module in secmet_benchmarks.BENCHMARKS:
      # print(benchmark_module)
      self.valid_benchmark_names.add(benchmark_module.BENCHMARK_NAME)

    self.valid_benchmark_set_names = set()
    # include the benchmark_set names since these can also appear
    # as a valid name.  At runtime they get expanded.
    for benchmark_set_name in benchmark_sets.BENCHMARK_SETS:
      self.valid_benchmark_set_names.add(benchmark_set_name)

    # Mock flags to simulate setting --benchmarks.
    p = patch(benchmark_sets.__name__ + '.FLAGS')
    self.mock_flags = p.start()
    self.addCleanup(p.stop)
    self.addCleanup(configs.GetConfigFlags.cache_clear)

    self.mock_flags.flag_matrix = None
    self.mock_flags.flag_zip = None
    self.mock_flags.num_benchmark_copies = 1

  def _CreateBenchmarkSpecFromYaml(self, yaml_string, benchmark_name=NAME):
    config = configs.LoadConfig(yaml_string, {}, benchmark_name)
    return self._CreateBenchmarkSpecFromConfigDict(config, benchmark_name)

  def _CreateBenchmarkSpecFromConfigDict(self, config_dict, benchmark_name):
    config_spec = benchmark_config_spec.BenchmarkConfigSpec(
        benchmark_name, flag_values=FLAGS, **config_dict)
    benchmark_module = next((b for b in secmet_benchmarks.BENCHMARKS
                             if b.BENCHMARK_NAME == benchmark_name))
    return benchmark_spec.BenchmarkSpec(benchmark_module, config_spec, UID)

class TestBenchmarks(_BenchmarkTestCase):
  def testStandardSet(self):
    self.assertIn(benchmark_sets.STANDARD_SET, benchmark_sets.BENCHMARK_SETS)
    standard_set = (benchmark_sets.BENCHMARK_SETS[benchmark_sets.STANDARD_SET])[
      benchmark_sets.BENCHMARK_LIST]
    self.assertIn('mttf', standard_set)
    self.assertIn('num_paths', standard_set)

  def testDefaultBenchmarks(self):
    print('Valid Benchmarks: ', self.valid_benchmark_names)

  def testLoadAllDefaultConfigs(self):
    all_benchmarks = (
        secmet_benchmarks.BENCHMARKS)
    for benchmark_module in all_benchmarks:
      self.assertIsInstance(benchmark_module.GetConfig({}), dict)

class TestBenchmarks(_BenchmarkTestCase):
  def testStandardSet(self):
    self.assertIn(benchmark_sets.STANDARD_SET, benchmark_sets.BENCHMARK_SETS)
    standard_set = (benchmark_sets.BENCHMARK_SETS[benchmark_sets.STANDARD_SET])[benchmark_sets.BENCHMARK_LIST]
    self.assertIn('mttf', standard_set)
    self.assertIn('num_paths', standard_set)

  def testDefaultBenchmarks(self):
    print('Valid Benchmarks: ', self.valid_benchmark_names)

  def testLoadAllDefaultConfigs(self):
    all_benchmarks = (secmet_benchmarks.BENCHMARKS)
    for benchmark_module in all_benchmarks:
      self.assertIsInstance(benchmark_module.GetConfig({}), dict)

  # def testLoadValidConfig(self):
  #   self.assertIsInstance(
  #       configs.LoadMinimalConfig(VALID_CONFIG, CONFIG_NAME), dict)
  #
  # def testWrongName(self):
  #   with self.assertRaises(KeyError):
  #     configs.LoadMinimalConfig(VALID_CONFIG, INVALID_NAME)
  #
  # def testLoadInvalidYaml(self):
  #   with self.assertRaises(errors.Config.ParseError):
  #     configs.LoadMinimalConfig(INVALID_YAML_CONFIG, CONFIG_NAME)
  #
  # def testMergeBasicConfigs(self):
  #   old_config = yaml.safe_load(CONFIG_A)
  #   new_config = yaml.safe_load(CONFIG_B)
  #   config = configs.MergeConfigs(old_config, new_config)
  #   # Key is present in both configs.
  #   self.assertEqual(config['a']['flags']['flag1'], 'new_value')
  #   # Key is only present in default config.
  #   self.assertEqual(config['a']['flags']['flag2'], 'not_overwritten')
  #   # Key is only present in the override config.
  #   self.assertEqual(config['a']['flags']['flag3'], 'new_flag')
  #
  # def testLoadConfigDoesMerge(self):
  #   default = yaml.safe_load(CONFIG_A)
  #   overrides = yaml.safe_load(CONFIG_B)
  #   merged_config = configs.MergeConfigs(default, overrides)
  #   config = configs.LoadConfig(CONFIG_A, overrides['a'], CONFIG_NAME)
  #   self.assertEqual(merged_config['a'], config)
  #
  # def testMergeConfigWithNoOverrides(self):
  #   old_config = yaml.safe_load(CONFIG_A)
  #   config = configs.MergeConfigs(old_config, None)
  #   self.assertEqual(config, old_config)
  #
  # def testLoadConfigWithExternalReference(self):
  #   self.assertIsInstance(configs.LoadMinimalConfig(REF_CONFIG, CONFIG_NAME),
  #       dict)
  #
  # def testLoadConfigWithBadReference(self):
  #   with self.assertRaises(errors.Config.ParseError):
  #     configs.LoadMinimalConfig(BAD_REF_CONFIG, CONFIG_NAME)
  #
  # def testConfigOverrideFlag(self):
  #   p = mock.patch(configs.__name__ + '.FLAGS')
  #   self.addCleanup(p.stop)
  #   mock_flags = p.start()
  #   config_override = ['a.vm_groups.default.vm_count=5', 'a.flags.flag=value']
  #   mock_flags.configure_mock(config_override=config_override,
  #                             benchmark_config_file=None)
  #   config = configs.GetUserConfig()
  #   self.assertEqual(config['a']['vm_groups']['default']['vm_count'], 5)
  #   self.assertEqual(config['a']['flags']['flag'], 'value')
  #
  # def testConfigImport(self):
  #   p = mock.patch(configs.__name__ + '.FLAGS')
  #   self.addCleanup(p.stop)
  #   mock_flags = p.start()
  #   mock_flags.configure_mock(benchmark_config_file='test_import.yml')
  #   config = configs.GetUserConfig()
  #   self.assertEqual(config['flags']['num_vms'], 3)

if __name__ == '__main__':
  unittest.main()


