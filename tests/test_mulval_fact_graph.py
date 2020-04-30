# from unittest import TestCase
from absl.testing import flagsaver
import sys
import os
import networkx as nx

from py_mulval import benchmark_spec
from py_mulval import configs
from py_mulval import context
from py_mulval import flags
# from py_mulval import linux_benchmarks
from py_mulval import secmet_benchmarks
from py_mulval.attack_graph import AttackGraph
# from py_mulval import pkb  # pylint: disable=unused-import # noqa
# from py_mulval import static_virtual_machine as static_vm
from py_mulval.configs import benchmark_config_spec
# from py_mulval.linux_benchmarks import iperf_benchmark
# from py_mulval.providers.gcp import util
from tests import common_test_case

import py_mulval.mulval_fact_graph
from py_mulval.mulval_fact_graph import FactGraph

# import tests.common_test_case

flags.DEFINE_integer('benchmark_spec_test_flag', 0, 'benchmark_spec_test flag.')

FLAGS = flags.FLAGS

NAME = 'metf_ml'
UID = '1234abcd'

SEP = os.path.sep
DATA_DIR = '/opt/projects/diss/py-mulval/data/facts'
FACTS_FILE = 'mulval_facts.json'

class _FactGraphTestCase(common_test_case.CommonTestCase):
  # @flagsaver.flagsaver(use_vpn=True, vpn_service_gateway_count=1)
  def setUp(self):
    super(_FactGraphTestCase, self).setUp()
    self.factgraph = FactGraph()
    facts_file = SEP.join((DATA_DIR, FACTS_FILE))
    self.factgraph.load_json_file(facts_file)

    if not sys.warnoptions:  # https://bugs.python.org/issue33154
      import warnings
      warnings.simplefilter("ignore", (ResourceWarning, DeprecationWarning))
    self.addCleanup(context.SetThreadBenchmarkSpec, None)

  def _CreateBenchmarkSpecFromYaml(self, yaml_string, benchmark_name=NAME):
    config = configs.LoadConfig(yaml_string, {}, benchmark_name)
    return self._CreateBenchmarkSpecFromConfigDict(config, benchmark_name)

  def _CreateBenchmarkSpecFromConfigDict(self, config_dict, benchmark_name):
    config_spec = benchmark_config_spec.BenchmarkConfigSpec(
        benchmark_name, flag_values=FLAGS, **config_dict)
    benchmark_module = next((b for b in secmet_benchmarks.BENCHMARKS
                             if b.BENCHMARK_NAME == benchmark_name))
    return benchmark_spec.BenchmarkSpec(benchmark_module, config_spec, UID)


class TestFactGraph(_FactGraphTestCase):
  def test_load_fact_graph(self):
    factgraph = FactGraph()
    facts_file = SEP.join((DATA_DIR, FACTS_FILE))
    factgraph.load_json_file(facts_file)
    self.assertIsNotNone(factgraph.facts_dict)

  def test_parse_hacl(self):
    hosts = self.factgraph.parseHacl()
    print(hosts)

  def test_to_agraph(self):
    A = nx.nx_agraph.to_agraph(self.factgraph)
    print('fg: ',self.factgraph)
    print('A: ', A)


