
"""Tests for py_mulval.attack_graph."""
import os
import sys

import networkx as nx
from absl.testing import flagsaver

import py_mulval
from py_mulval import attack_graph
from py_mulval import benchmark_spec
from py_mulval import benchmark_sets
import py_mulval
import py_mulval.py_mulval
import py_mulval.boromir
from py_mulval import configs
from py_mulval import context
from py_mulval import data
from py_mulval import flags
# from py_mulval import linux_benchmarks
from py_mulval import secmet_benchmarks
# from py_mulval import pkb  # pylint: disable=unused-import # noqa
# from py_mulval import static_virtual_machine as static_vm
from py_mulval import vm_util
from py_mulval.attack_graph import AttackGraph
from py_mulval.configs import benchmark_config_spec
# from py_mulval.linux_benchmarks import iperf_benchmark
# from py_mulval.providers.gcp import util
from py_mulval.graphml import graph_stochastics
from py_mulval.metrics.ag_metrics.mttf import mttf_metric
from py_mulval.metrics.ag_metrics.nra_amc import *
from tests import common_test_case
SEP = os.path.sep
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

ag_dot_str = """
digraph G {
	1 [label="1:execCode(workStation,root):0",shape=diamond];
	2 [label="2:RULE 4 (Trojan horse installation):0",shape=ellipse];
	3 [label="3:accessFile(workStation,write,'/usr/local/share'):0",shape=diamond];
	4 [label="4:RULE 16 (NFS semantics):0",shape=ellipse];
	5 [label="5:accessFile(fileServer,write,'/export'):0",shape=diamond];
	6 [label="6:RULE 10 (execCode implies file access):0",shape=ellipse];
	7 [label="7:canAccessFile(fileServer,root,write,'/export'):1",shape=box];
	8 [label="8:execCode(fileServer,root):0",shape=diamond];
	9 [label="9:RULE 2 (remote exploit of a server program):0",shape=ellipse];
	10 [label="10:netAccess(fileServer,rpc,100005):0",shape=diamond];
	11 [label="11:RULE 5 (multi-hop access):0",shape=ellipse];
	12 [label="12:hacl(webServer,fileServer,rpc,100005):1",shape=box];
	13 [label="13:execCode(webServer,apache):0",shape=diamond];
	14 [label="14:RULE 2 (remote exploit of a server program):0",shape=ellipse];
	15 [label="15:netAccess(webServer,tcp,80):0",shape=diamond];
	16 [label="16:RULE 6 (direct network access):0",shape=ellipse];
	17 [label="17:hacl(internet,webServer,tcp,80):1",shape=box];
	18 [label="18:attackerLocated(internet):1",shape=box];
	19 [label="19:networkServiceInfo(webServer,httpd,tcp,80,apache):1",shape=box];
	20 [label="20:vulExists(webServer,'CAN-2002-0392',httpd,remoteExploit,privEscalation):1",shape=box];
	21 [label="21:networkServiceInfo(fileServer,mountd,rpc,100005,root):1",shape=box];
	22 [label="22:vulExists(fileServer,vulID,mountd,remoteExploit,privEscalation):1",shape=box];
	23 [label="23:RULE 17 (NFS shell):0",shape=ellipse];
	24 [label="24:hacl(webServer,fileServer,nfsProtocol,nfsPort):1",shape=box];
	25 [label="25:nfsExportInfo(fileServer,'/export',write,webServer):1",shape=box];
	26 [label="26:nfsMounted(workStation,'/usr/local/share',fileServer,'/export',read):1",shape=box];
	7 -> 	6;
	12 -> 	11;
	17 -> 	16;
	18 -> 	16;
	16 -> 	15;
	15 -> 	14;
	19 -> 	14;
	20 -> 	14;
	14 -> 	13;
	13 -> 	11;
	11 -> 	10;
	10 -> 	9;
	21 -> 	9;
	22 -> 	9;
	9 -> 	8;
	8 -> 	6;
	6 -> 	5;
	24 -> 	23;
	25 -> 	23;
	13 -> 	23;
	23 -> 	5;
	5 -> 	4;
	26 -> 	4;
	4 -> 	3;
	3 -> 	2;
	2 -> 	1;
}
"""

fg_dot_str = """
digraph "mulval_facts.multi_host_1.dot" {
	graph [name="mulval_facts.multi_host_1.dot"];
	webServer	 [color=blue,
		s=s,
		shape=box,
		type=HOST];
	webServer -> webServer [key=0];
fileServer [color=blue,
	s=s,
	shape=box,
	type=HOST];
webServer -> fileServer [key=0];
internet [color=blue,
s=s,
shape=box,
type=HOST];
webServer -> internet [key=0];
workStation [color=blue,
s=s,
shape=box,
type=HOST];
webServer -> workStation [key=0];
fileServer -> webServer [key=0];
fileServer -> fileServer [key=0];
fileServer -> internet [key=0];
fileServer -> workStation [key=0];
internet -> webServer [key=0];
workStation -> webServer [key=0];
workStation -> fileServer [key=0];
workStation -> internet [key=0];
workStation -> workStation [key=0];
}
"""


class _MetricTestCase(common_test_case.CommonTestCase):
  # @flagsaver.flagsaver(use_vpn=True, vpn_service_gateway_count=1)
  def setUp(self):
    super(_MetricTestCase, self).setUp()

    if not sys.warnoptions:  # https://bugs.python.org/issue33154
      import warnings
      warnings.simplefilter("ignore", (ResourceWarning, DeprecationWarning))
    self.addCleanup(context.SetThreadBenchmarkSpec, None)

    # create set of valid metric modulse names from the benchmark directory
    self.valid_metric_names = set()
    for metric_module in py_mulval.metrics.METRICS:
      # print(metric_module)
      self.valid_metric_names.add(metric_module)

  def _CreateAGFromDotString(self, dots=ag_dot_str):
    ag = AttackGraph()
    ag.scriptsDir = data.ResourcePath('secmet')
    ag.load_score_dict(SEP.join((data.ResourcePath('secmet'), attack_graph.SCORE_DICT)))
    # ag.inputDir = input_models_dir
    # ag.outputDir = vm_util.GetTempDir()
    ag.load_dot_string(dots)
    return ag


  def _CreateBenchmarkSpecFromYaml(self, yaml_string, benchmark_name=NAME):
    config = configs.LoadConfig(yaml_string, {}, benchmark_name)
    return self._CreateBenchmarkSpecFromConfigDict(config, benchmark_name)

  def _CreateBenchmarkSpecFromConfigDict(self, config_dict, benchmark_name):
    config_spec = benchmark_config_spec.BenchmarkConfigSpec(
        benchmark_name, flag_values=FLAGS, **config_dict)
    benchmark_module = next((b for b in secmet_benchmarks.BENCHMARKS
                             if b.BENCHMARK_NAME == benchmark_name))
    return benchmark_spec.BenchmarkSpec(benchmark_module, config_spec, UID)



class TestMetrics(_MetricTestCase):

  @flagsaver.flagsaver(secmet_random_seed='rando12345', run_uri='test5678')
  def test_sim_tmatrix(self):
    ag = attack_graph.AttackGraph()
    ag.load_dot_file('/opt/projects/diss/py-mulval/data/mulval_ag/small_enterprise/AttackGraph.dot')
    ag.name = 'small_enterprise'
    ag.load_score_dict('/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/scoreDict.yml')
    ag.PLOT_INTERMEDIATE_GRAPHS = False
    ag.map_scores = 'cvss2time'
    reduced_ag = ag.getReducedGraph()
    node_list = list(nx.topological_sort(reduced_ag))

    # reduced_ag = ag.getReducedGraph()
    # self.normalize_scores_graph1(reduced_ag, weight='score_orig')
    # node_list = list(nx.topological_sort(reduced_ag))
    # plot_ag(reduced_ag, 'Reduced Attack Graph is the Markov Transition Matrix', )
    # P_orig = nx.adjacency_matrix(reduced_ag, nodelist=node_list, weight='score')
    # P_normal = nx.adjacency_matrix(reduced_ag, nodelist=node_list, weight='weighted_score')

    # metric = mttf_metric()
    # self.assertIsNotNone(metric)
    # ag = self._CreateAGFromDotString()
    # graph_stochastics
    # metric.ag = ag
    # result, metadata = metric.calculate()

    state = [2000, 0, 0, 0, 0, 0]

    transition = [
        [0.0, 0.5, 0.5, 0.0, 0.0, 0.0], [0.0, 0.2, 0.2, 0.6, 0.0, 0.0], [0.0, 0.0, 0.4, 0.0, 0.4, 0.2],
        [0.2, 0.1, 0.0, 0.3, 0.0, 0.4], [0.0, 0.0, 0.0, 0.0, 1.0, 0.0], [0.0, 0.0, 0.0, 0.0, 0.0, 1.0]
    ]

    stateTrack, length, state = graph_stochastics.AGMarkov(ag)
    # stateTrack, length, state = graph_stochastics.MarkovChain(state, transition, 30)
    # print(stateTrack, length, state)
    graph_stochastics.PlotMarkov(stateTrack, length, state)










#
# if __name__ == '__main__':
#   unittest.main()
