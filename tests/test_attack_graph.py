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

ag_dot_string = """
digraph single_host_1 {
	graph [name=single_host_1];
	1	 [color=blue,
		label="1:execCode(workStation,root):0",
		s=d,
		scores="[]",
		shape=diamond,
		type=OR];
	2	 [color=red,
		exploit_rule_score=None,
		exploit_rule_score_orig=None,
		label="2:RULE 4 (Trojan horse installation):0",
		s=o,
		shape=ellipse,
		type=AND];
	2 -> 1 [key=0];
3 [color=blue,
	label="3:accessFile(workStation,write,'/usr/local/share'):0",
	s=d,
	scores="[]",
	shape=diamond,
	type=OR];
3 -> 2 [key=0];
4 [color=red,
exploit_rule_score=None,
exploit_rule_score_orig=None,
label="4:RULE 16 (NFS semantics):0",
s=o,
shape=ellipse,
type=AND];
4 -> 3 [key=0];
5 [color=blue,
label="5:accessFile(fileServer,write,'/export'):0",
s=d,
scores="[]",
shape=diamond,
type=OR];
5 -> 4 [key=0];
6 [color=red,
exploit_rule_score=None,
exploit_rule_score_orig=None,
label="6:RULE 10 (execCode implies file access):0",
s=o,
shape=ellipse,
type=AND];
6 -> 5 [key=0];
7 [color=green,
label="7:canAccessFile(fileServer,root,write,'/export'):1",
s=s,
shape=box,
type=LEAF];
7 -> 6 [key=0];
8 [color=blue,
label="8:execCode(fileServer,root):0",
s=d,
scores="[]",
shape=diamond,
type=OR];
8 -> 6 [key=0];
9 [color=red,
exploit_rule_score=None,
exploit_rule_score_orig=None,
label="9:RULE 2 (remote exploit of a server program):0",
s=o,
shape=ellipse,
type=AND];
9 -> 8 [key=0];
10 [color=blue,
label="10:netAccess(fileServer,rpc,100005):0",
s=d,
scores="[]",
shape=diamond,
type=OR];
10 -> 9 [key=0];
11 [color=red,
exploit_rule_score=None,
exploit_rule_score_orig=None,
label="11:RULE 5 (multi-hop access):0",
s=o,
shape=ellipse,
type=AND];
11 -> 10 [key=0];
12 [color=green,
label="12:hacl(webServer,fileServer,rpc,100005):1",
s=s,
shape=box,
type=LEAF];
12 -> 11 [key=0];
13 [color=blue,
label="13:execCode(webServer,apache):0",
s=d,
scores="[]",
shape=diamond,
type=OR];
13 -> 11 [key=0];
23 [color=red,
exploit_rule_score=None,
exploit_rule_score_orig=None,
label="23:RULE 17 (NFS shell):0",
s=o,
shape=ellipse,
type=AND];
13 -> 23 [key=0];
23 -> 5 [key=0];
14 [color=red,
exploit_rule_score=None,
exploit_rule_score_orig=None,
label="14:RULE 2 (remote exploit of a server program):0",
s=o,
shape=ellipse,
type=AND];
14 -> 13 [key=0];
15 [color=blue,
label="15:netAccess(webServer,tcp,80):0",
s=d,
scores="[]",
shape=diamond,
type=OR];
15 -> 14 [key=0];
16 [color=red,
exploit_rule_score=None,
exploit_rule_score_orig=None,
label="16:RULE 6 (direct network access):0",
s=o,
shape=ellipse,
type=AND];
16 -> 15 [key=0];
17 [color=green,
label="17:hacl(internet,webServer,tcp,80):1",
s=s,
shape=box,
type=LEAF];
17 -> 16 [key=0];
18 [color=green,
label="18:attackerLocated(internet):1",
s=s,
shape=box,
type=LEAF];
18 -> 16 [key=0];
19 [color=green,
label="19:networkServiceInfo(webServer,httpd,tcp,80,apache):1",
s=s,
shape=box,
type=LEAF];
19 -> 14 [key=0];
20 [color=green,
label="20:vulExists(webServer,'CAN-2002-0392',httpd,remoteExploit,privEscalation):1",
s=s,
shape=box,
type=LEAF];
20 -> 14 [key=0];
21 [color=green,
label="21:networkServiceInfo(fileServer,mountd,rpc,100005,root):1",
s=s,
shape=box,
type=LEAF];
21 -> 9 [key=0];
22 [color=green,
label="22:vulExists(fileServer,vulID,mountd,remoteExploit,privEscalation):1",
s=s,
shape=box,
type=LEAF];
22 -> 9 [key=0];
24 [color=green,
label="24:hacl(webServer,fileServer,nfsProtocol,nfsPort):1",
s=s,
shape=box,
type=LEAF];
24 -> 23 [key=0];
25 [color=green,
label="25:nfsExportInfo(fileServer,'/export',write,webServer):1",
s=s,
shape=box,
type=LEAF];
25 -> 23 [key=0];
26 [color=green,
label="26:nfsMounted(workStation,'/usr/local/share',fileServer,'/export',read):1",
s=s,
shape=box,
type=LEAF];
26 -> 4 [key=0];
}
"""

reduced_ag_string = """
digraph single_host_1 {
	graph [name=single_host_1];
	1	 [color=blue,
		label="1:execCode(workStation,root):0",
		mttf=0,
		s=d,
		scores="[50.0]",
		shape=diamond,
		t_k=0,
		type=OR];
	3	 [color=blue,
		label="3:accessFile(workStation,write,'/usr/local/share'):0",
		mttf=0.02,
		s=d,
		scores="[5.0]",
		shape=diamond,
		t_k=0.02,
		type=OR];
	3 -> 1 [key=0,
	label=50.0,
	score=50.0,
	score_orig=3.12,
	weight=50.0];
5 [color=blue,
	label="5:accessFile(fileServer,write,'/export'):0",
	mttf=0.22,
	s=d,
	scores="[5.0, 0.02]",
	shape=diamond,
	t_k=0.2,
	type=OR];
5 -> 3 [key=0,
label=5.0,
score=5.0,
score_orig=4.29,
weight=5.0];
8 [color=blue,
label="8:execCode(fileServer,root):0",
mttf=0.42000000000000004,
s=d,
scores="[5000.0]",
shape=diamond,
t_k=0.2,
type=OR];
8 -> 5 [key=0,
label=5.0,
score=5.0,
score_orig=4.33,
weight=5.0];
13 [color=blue,
label="13:execCode(webServer,apache):0",
mttf=0.4201991992032032,
s=d,
scores="[0.02]",
shape=diamond,
t_k=0.00019999920000319998,
type=OR];
13 -> 5 [key=0,
label=0.02,
score=0.02,
score_orig=9.15,
weight=0.02];
13 -> 8 [key=0,
label=5000.0,
score=5000.0,
score_orig=1.1,
weight=5000.0];
0 [mttf=50.4201991992032,
t_k=50.0,
type=ROOT];
0 -> 13 [key=0,
label=0.02,
score=0.02,
score_orig=9.69,
weight=0.02];
}
"""

import networkx as nx
import graphviz

import stellargraph as sg

from stellargraph import StellarGraph

def plot_dot(ag, title=None):
  A = nx.nx_agraph.to_agraph(ag)
  if title:
    A.graph_attr.update(label=title, labelloc='top', labeljust='center',
                        fontsize=24)
  # A.layout('dot', args='-Nfontsize=10 -Nwidth=".2" -Nheight=".2" -Nmargin=0
  # -Gfontsize=8')
  args = """
  -Gsize=17
  -Nfontname=Roboto
  -Efontname=Roboto
  -Nfontsize=14
  -Efontsize=14
  """
  A.layout('dot', args=args)
  # A.draw(self.outputDir + '/' + outfilename)
  A.draw()
  # plt.show()
  return graphviz.Source(A.to_string())

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

  def testLoadDotString(self):
    # orig ag
    ag = AttackGraph()
    ag.load_dot_string(ag_dot_string)
    # print(ag.nodes(data=True))

    # reduced ag
    ag = AttackGraph()
    ag.load_dot_string(reduced_ag_string)
    # print(ag.nodes(data=True))

  def test_plot_dot(self):
    ag = AttackGraph()
    ag.load_dot_string(ag_dot_string)
    plot_dot(ag, 'test title')


  def test_load_dot_file(self):
    ag = AttackGraph()
    ag.load_dot_file(
        '/opt/projects/diss/py-mulval/data/mulval_ag/small_enterprise'
        '/AttackGraph.dot')

    A = nx.nx_agraph.to_agraph(ag)
    A.layout('dot', args='-Nfontsize=10 -Nwidth=".2" -Nheight=".2" -Nmargin=0 '
                         '-Gfontsize=8')  # A.draw(self.outputDir + '/' +  # outfilename)


  def test_stellargraph_load_nx(self):
    ag = AttackGraph()
    ag.load_dot_string(reduced_ag_string)

    print(ag.edges(data=True))

    sg_ag = StellarGraph.from_networkx(ag)

    print(sg_ag.info())


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
