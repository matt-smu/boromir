
"""Tests for py_mulval.attack_graph."""
import sys

from py_mulval import benchmark_spec
from py_mulval import benchmark_sets
from py_mulval import configs
from py_mulval import context
from py_mulval import flags
# from py_mulval import linux_benchmarks
from py_mulval import secmet_benchmarks
# from py_mulval import pkb  # pylint: disable=unused-import # noqa
# from py_mulval import static_virtual_machine as static_vm
from py_mulval.configs import benchmark_config_spec
# from py_mulval.linux_benchmarks import iperf_benchmark
# from py_mulval.providers.gcp import util
from tests import common_test_case

# import tests.common_test_case


flags.DEFINE_integer('benchmark_spec_test_flag', 0, 'benchmark_spec_test flag.')

FLAGS = flags.FLAGS

_rule = 'local_exploit_rules.P'
_input_file = 'single_host_1.P'
_models_dir= '/opt/projects/diss/py-mulval/data/models'
_rules_dir = '/opt/projects/diss/py-mulval/data/rules '
_data_dir = '/opt/projects/diss/py-mulval/data'
_secmet_ag_path = 'AttackGraph.dot'

implemented_metrics = ['mttf', 'metf_ml', 'metf_tm', 'num_paths',
                       'shortest_path_cumulative', 'shortest_path_direct']


NAME = 'metf_ml'
UID = '1234abcd'
# import common_test_case

__default_config = """
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


class _MetricTestCase(common_test_case.CommonTestCase):
  # @flagsaver.flagsaver(use_vpn=True, vpn_service_gateway_count=1)
  def setUp(self):
    super(_MetricTestCase, self).setUp()

    if not sys.warnoptions:  # https://bugs.python.org/issue33154
      import warnings
      warnings.simplefilter("ignore", (ResourceWarning, DeprecationWarning))
    self.addCleanup(context.SetThreadBenchmarkSpec, None)

    # create set of valid benchmark names from the benchmark directory
    self.valid_metric_names = set()
    for metric_module in secmet_benchmarks.BENCHMARKS:
      # print(benchmark_module)
      self.valid_benchmark_names.add(metric_module.M)

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



class TestBenchmarks(_MetricTestCase):
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



if __name__ == '__main__':
  unittest.main()
