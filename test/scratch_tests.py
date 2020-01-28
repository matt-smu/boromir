import os
import sys
import networkx as nx

# py_mulval_path = r'/opt/projects/diss/py-mulval/src'
# sys.path.append(py_mulval_path)

from py_mulval.attack_graph import AttackGraph

# def test_attack_graph(self):
ag = AttackGraph()
print(ag.name)
ag.load_dot_file(
    '/opt/projects/diss/py-mulval/data/mulval_ag/small_enterprise'
    '/AttackGraph.dot')

A = nx.nx_agraph.to_agraph(ag)
A.layout('dot', args='-Nfontsize=10 -Nwidth=".2" -Nheight=".2" -Nmargin=0 '
                     '-Gfontsize=8')  #         A.draw(self.outputDir + '/' + outfilename)

print(ag.data)