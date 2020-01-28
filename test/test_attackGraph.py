from unittest import TestCase


class TestAttackGraph(TestCase):
  def test_load_dot_file(self):
    def test_attack_graph(self):
      ag = AttackGraph()
      ag.load_dot_file(
          '/opt/projects/diss/py-mulval/data/mulval_ag/small_enterprise'
          '/AttackGraph.dot')

      A = nx.nx_agraph.to_agraph(self)
      A.layout('dot',
               args='-Nfontsize=10 -Nwidth=".2" -Nheight=".2" -Nmargin=0 '
                    '-Gfontsize=8')  #         A.draw(self.outputDir + '/' +
      # outfilename)


