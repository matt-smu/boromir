# from unittest import TestCase

"""Tests for py_mulval.attack_graph."""
from absl.testing import flagsaver
import sys
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

# import tests.common_test_case


flags.DEFINE_integer('benchmark_spec_test_flag', 0, 'benchmark_spec_test flag.')

FLAGS = flags.FLAGS

NAME = 'metf_ml'
UID = '1234abcd'
# import common_test_case

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


class _AttackGraphTestCase(common_test_case.CommonTestCase):
  # @flagsaver.flagsaver(use_vpn=True, vpn_service_gateway_count=1)
  def setUp(self):
    super(_AttackGraphTestCase, self).setUp()

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


class TestAttackGraph(_AttackGraphTestCase):
  def test_load_score_dict(self):

    pass
  def test_load_dot_file(self):
    ag = AttackGraph()
    ag.load_dot_file(
        '/opt/projects/diss/py-mulval/data/mulval_ag/small_enterprise'
        '/AttackGraph.dot')

    A = nx.nx_agraph.to_agraph(ag)
    A.layout('dot', args='-Nfontsize=10 -Nwidth=".2" -Nheight=".2" -Nmargin=0 '
                         '-Gfontsize=8')  # A.draw(self.outputDir + '/' +  # outfilename)


  # def test_plot2(self):
  #     self.fail()
  #
  # def test_get_plot_node_labels(self):
  #   self.fail()
  #
  # def test_get_cvssscore(self):
  #   self.fail()
  #
  # def test_map_score(self):
  #   self.fail()
  #
  # def test_get_andnodes(self):
  #   self.fail()
  #
  # def test_get_ornodes(self):
  #   self.fail()
  #
  # def test_get_leafnodes(self):
  #   self.fail()
  #
  # def test_get_originnodes_by_attacker_located(self):
  #   self.fail()
  #
  # def test_get_target_by_no_egress_edges(self):
  #   self.fail()
  #
  # def test_set_andscores(self):
  #   self.fail()
  #
  # def test_score_ands(self):
  #   self.fail()
  #
  # def test_merge_two_dicts(self):
  #   self.fail()
  #
  # def test_coalesce_andnodes(self):
  #   self.fail()
  #
  # def test_coalesce_ornodes(self):
  #   self.fail()
  #
  # def test_prune_leafs(self):
  #   self.fail()
  #
  # def test_set_origin(self):
  #   self.fail()
  #
  # def test_set_edge_score(self):
  #   self.fail()
  #
  # def test_get_out_edge_vals_for_key(self):
  #   self.fail()
  #
  # def test_get_in_edge_vals_for_key(self):
  #   self.fail()
  #
  # def test_set_edge_scores(self):
  #   self.fail()
  #
  # def test_set_edge_weights(self):
  #   self.fail()
  #
  # def test_get_self_edge(self):
  #   self.fail()
  #
  # def test_get_reduced_graph(self):
  #   self.fail()
  #
  # def test_translate_cvss(self):
  #   self.fail()
  #
  # def test_score_tgraph(self):
  #   self.fail()
  #
  # def test_weigh_tgraph(self):
  #   self.fail()
  #
  # def test_get_trans_matrix(self):
  #   self.fail()
  #
  # def test_get_node_list(self):
  #   self.fail()
  #
  # def test_convert_tmatrix(self):
  #   self.fail()
  #
  # def test_write_tmatrix(self):
  #   self.fail()
  #
  # def test_print_help(self):
  #   self.fail()
