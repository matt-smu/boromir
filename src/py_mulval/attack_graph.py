#!/usr/bin/env python
import logging
import os
import re
import sys
import warnings
from copy import deepcopy
from pathlib import Path

import MySQLdb
import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import pandas
import scipy
import yaml
from networkx.drawing.nx_agraph import read_dot

from py_mulval import flags

# matplotlib.use('TkAgg')

# flags.DEFINE_float('secmet_fix_cvss_score', None, 'applies this score to all vulnerabilities',lower_bound=0.0, upper_bound=10.0)

warnings.simplefilter('ignore', scipy.sparse.SparseEfficiencyWarning)
ARCS = 'ARCS.CSV'
VERTS = 'VERTICES.CSV'
AG_DOT = 'AttackGraph.dot'
SCORE_DICT = 'scoreDict.yml'

FLAGS = flags.FLAGS

exploitDict = {}
conf_override = {}
coalesced_rules = []
exploit_rules = {}


class AttackGraph(nx.MultiDiGraph):
    """
    Class for working with MulVal Attack Graphs.
    """

    def __init__(self, *args, **kwargs):

        # logging.debug((self.nodes()))

        self.scriptsDir = '.'  # os.cwd()
        if 'scriptsDir' in kwargs.keys():
            self.scriptsDir = kwargs['scriptsDir']
            logging.debug(('scriptsDir: ', self.scriptsDir))

        self.inputDir = '.' #os.cwd()
        if 'inputDir' in kwargs.keys():
            self.inputDir = kwargs['inputDir']
            logging.debug(('inputDir: ', self.inputDir))

        self.outputDir = self.inputDir #os.cwd()
        if 'outputDir' in kwargs.keys():
            self.outputDir = kwargs['outputDir']
            logging.debug(('output: ', self.outputDir))

        # if os.path.exists(self.scriptsDir + '/' + SCORE_DICT):
        if Path(self.scriptsDir + '/' + SCORE_DICT).exists():
            with open(self.scriptsDir + '/' + SCORE_DICT) as f:
                # logging.debug((f.readlines()))
                self.conf_override = yaml.safe_load(f)
                # logging.debug(('conf_overrides', self.conf_override))
                self.coalesced_rules = self.conf_override['coalesce_rules']
                # logging.debug(('coalesced rules loaded: ', self.coalesced_rules))
                self.exploit_rules = self.conf_override['exploit_rules']
                self.exploitDict = self.conf_override['exploitDict']

        # Prevent slowdown from writing lots of pictures to disk
        self.PLOT_INTERMEDIATE_GRAPHS = True
        if 'PLOT_INTERMEDIATE_GRAPHS' in kwargs.keys():
            self.PLOT_INTERMEDIATE_GRAPHS = kwargs['PLOT_INTERMEDIATE_GRAPHS']
            logging.debug(('PLOT_INTERMEDIATE_GRAPHS: ', self.PLOT_INTERMEDIATE_GRAPHS))


        self.origin = None
        self.target = None
        self.node_list = []
        self.data = None
        self.fix_cvss_score = None
        if Path(os.path.join(self.inputDir, AG_DOT)).exists():
            self.data = read_dot(os.path.join(self.inputDir, AG_DOT))
        super(AttackGraph, self).__init__(self.data)

        # add fields not included in dot file
        self.__updateAG()

    def load_score_dict(self, score_dict_path):
        # if os.path.exists(self.scriptsDir + '/' + SCORE_DICT):
        if Path(score_dict_path).exists():
            with open(score_dict_path) as f:
                # logging.debug((f.readlines()))
                self.conf_override = yaml.safe_load(f)
                # logging.debug(('conf_overrides', self.conf_override))
                self.coalesced_rules = self.conf_override['coalesce_rules']
                # logging.debug(('coalesced rules loaded: ',
                # self.coalesced_rules))
                self.exploit_rules = self.conf_override['exploit_rules']
                self.exploitDict = self.conf_override['exploitDict']

    # def plot1(self, **kwargs):
    #
    #     # labels = self.getPlotNodeLabels()
    #     # nodePos = nx.layout.spring_layout(self)
    #     nodePos = graphviz_layout(self, prog='dot')
    #
    #     nodeShapes = set((aShape[1]["s"] for aShape in self.nodes(data=True)))
    #     logging.debug((nodeShapes))
    #
    #     labels = self.nodes.keys()
    #     labels = None
    #
    #     # For each node class...
    #     for aShape in nodeShapes:
    #         # ...filter and draw the subset of nodes with the same symbol in the positions
    #         # that are now known through the use of the layout.
    #         nx.draw_networkx_nodes(self, nodePos, with_labels=True, font_weight='bold',
    #         labels=labels, node_shape=aShape, nodelist=[sNode[0] for sNode in
    #         filter(lambda x: x[1]["s"] == aShape, self.nodes(data=True))])
    #
    #     # Finally, draw the edges between the nodes
    #     nx.draw_networkx_edges(self,  nodePos, with_labels=True, font_weight='bold',)
    #
    #     # nx.draw(self, with_labels=True, font_weight='bold', labels=None)
    #     plt.show()

    def load_dot_file(self, dot_file_path):
        logging.info('loading dot file: %s', dot_file_path)
        self.data = read_dot(dot_file_path)
        super(AttackGraph, self).__init__(self.data)
        self.__updateAG()

    def plot2(self, *args, **kwargs):
        if not self.PLOT_INTERMEDIATE_GRAPHS:
            # bail if we don't want noisy output
            return
        if 'outfilename' in kwargs:
            outfilename = kwargs.get("outfilename")
        else:
            outfilename = 'test.png'

        A = nx.nx_agraph.to_agraph(self)
        A.layout('dot', args='-Nfontsize=10 -Nwidth=".2" -Nheight=".2" -Nmargin=0 -Gfontsize=8')
        A.draw(self.outputDir + '/' + outfilename)
        plt.show()

    def __updateAG(self):
        for node in self.nodes.keys():
            if self.nodes[node]['shape'] == 'diamond':
                self.nodes[node]['type'] = 'OR'
                self.nodes[node]['color'] = 'blue'
                self.nodes[node]['s'] = 'd'
                self.nodes[node]['scores'] = []
            elif self.nodes[node]['shape'] == 'ellipse':
                self.nodes[node]['type'] = 'AND'
                self.nodes[node]['color'] = 'red'
                self.nodes[node]['s'] = 'o'
                self.nodes[node]['exploit_rule_score'] = None
            elif self.nodes[node]['shape'] == 'box':
                self.nodes[node]['type'] = 'LEAF'
                self.nodes[node]['color'] = 'green'
                self.nodes[node]['s'] = 's'
            else:
                logging.debug(('Unknown node type: ', self.nodes[node]['shape']))

    def getPlotNodeLabels(self):
        labels = {}
        colors = []

        for node in self.nodes.keys():
            labels[node] = self.nodes[node]['label']

        return labels

    def getCVSSscore(self, cveid):
        if self.fix_cvss_score:
            return self.fix_cvss_score
        score = 'null'  # the score to return
        con = None
        logging.debug(('looking for cveid: ', cveid))

        if cveid in self.exploitDict.keys():  # check user overrides first
            score = self.exploitDict[cveid]
            # logging.debug(('Matched hypothetical score ' + cveid + ' : ' + str(score)))
        else:
            try:
                con = MySQLdb.connect('localhost', 'nvd', 'nvd', 'nvd')
                cur = con.cursor(MySQLdb.cursors.DictCursor)
                cur.execute("select score from nvd where id = '%s'" % (cveid))
                res = cur.fetchone()  # the cveid or None it
                if res:
                    score = res['score']
                    logging.debug(('Found cveid ' + cveid + ' with score: ' + str(score)))

                else:
                    logging.debug(('bad cveid (result unknown): setting CVSS to 1!!!**** [' + cveid + ']'))
                    score = 1
            except MySQLdb.Error as e:
                logging.debug(("Error %d: %s" % (e.args[0], e.args[1])))

                # @TODO exit when not testing (uncomment)
                # sys.exit(1)
                logging.debug(('bad cveid (result unknown): setting CVSS to 1!!!**** [' + cveid + ']'))
                score = 1
            finally:
                if con:
                    con.close()

        return score

    def getANDnodes(self):
        andNodes = [n for n, v in self.nodes(data=True) if v['type'] == 'AND']
        # logging.debug((andNodes))
        return andNodes

    def getORnodes(self):
        orNodes = [n for n, v in self.nodes(data=True) if v['type'] == 'OR']
        # logging.debug((orNodes))
        return orNodes

    def getLEAFnodes(self):
        leafNodes = [n for n, v in self.nodes(data=True) if v['type'] == 'LEAF']
        # logging.debug((leafNodes))
        return leafNodes

    def getOriginnodesByAttackerLocated(self):
        ONodes = [n for n, v in self.nodes(data=True) if 'attackerLocated' in v['label']]
        # logging.debug((ONodes))
        return ONodes

    def getTargetByNoEgressEdges(self):
        targetNodes = [n for n, v in self.nodes(data=True) if len(self.out_edges(n, keys=True, data=True)) == 0]
        return targetNodes

    def setANDscores(self):
        """Sets the AND node score to the matching CVSS base score"""

        andNodes = self.getANDnodes()
        for andNode in andNodes:
            # set if we are explicit coalesce rule
            # logging.debug(('Checking: ', self.nodes[andNode]['label'], self.coalesced_rules))
            self.nodes[andNode]['toCoalesce'] = True
            logging.debug(('setting node to coalesce: ', self.nodes[andNode]))

            # set if there is a general exploit_rule score
            if any(xr in self.nodes[andNode]['label'] for xr in self.exploit_rules.keys()):
                self.nodes[andNode]['toCoalesce'] = False
                # logging.debug(('setting node to default exploit score: ', self.nodes[andNode]))
                for xr in self.exploit_rules.keys():
                    if xr in self.nodes[andNode]['label']:
                        if self.fix_cvss_score:
                            self.nodes[andNode]['exploit_rule_score'] = self.fix_cvss_score
                        else:
                            self.nodes[andNode]['exploit_rule_score'] = self.exploit_rules[xr]
                            # logging.debug(('setting node to default exploit score: ', self.nodes[andNode]))

                # look for cvss score in leafs
                leafPreds = [n for n in self.predecessors(andNode) if self.nodes[n]['type'] == 'LEAF']
                score = None
                for p in leafPreds:
                    matchObj = re.match(r'.*:vulExists\((.*),(.*),(.*),(.*),(.*)\):.*', self.nodes[p]['label'],
                                        re.M | re.I)
                    # logging.debug(('looking for cve id in: ', self.nodes[p]['label'], matchObj))
                    # assuming only 1 vuln per AND...
                    if matchObj:
                        mycveid = matchObj.group(2).strip('\'')
                        # logging.debug(('finding score for cveid: ', mycveid))
                        score = self.getCVSSscore(mycveid)

                if score:
                    logging.debug(('score found, overwriting default for node: ', score,
                                   self.nodes[andNode]['exploit_rule_score'], andNode))
                    self.nodes[andNode]['exploit_rule_score'] = score
                else:
                    logging.debug(('no score found, preserving default', self.nodes[andNode]))

                #  set outbound edge scores here
                o_edges = [((u, v, k), e) for u, v, k, e in self.out_edges(andNode, keys=True, data=True)]
                for ((u2, v2, k2), e2) in o_edges:
                    self.setEdgeScore(u2, v2, k2, self.nodes[andNode]['exploit_rule_score'])

    def scoreANDs(self):
        """Normalizes the score in [0..1] with adjacent incoming node scores"""
        andNodes = self.getANDnodes()
        logging.debug(('scoreANDs remaining AND nodes: ', andNodes))
        for a in andNodes:
            logging.debug((self.nodes[a]))
            i_edges = [((u, v, k), e) for u, v, k, e in self.in_edges(a, keys=True, data=True)]
            o_edges = [((u, v, k), e) for u, v, k, e in self.out_edges(a, keys=True, data=True)]
            logging.debug(('a in out: ', a, i_edges, o_edges))
            # for (u1, v1), (u2, v2) in zip(i_edges, o_edges):
            if not i_edges or not o_edges:  # we're at root
                if not i_edges and not o_edges:
                    logging.debug(('scoreANDs !!!!!!!!!! Isolated Node !!!!!!!!!!!!!!'))
                if not i_edges:
                    for ((u2, v2, k2), e2) in o_edges:
                        logging.debug(('u2, v2, k2, e2: ', u2, v2, k2, e2))
                        self.nodes[v2]['scores'].append(self.nodes[a]['exploit_rule_score'])
                        logging.debug(('added score to child OR node: ', self.nodes[v2]))
                        # logging.debug(('making new edge: ', (u1, v2)))
                        self.remove_edge(u2, v2, k2)
                        o_edges.remove(((u2, v2, k2), e2))
                if not o_edges:
                    for ((u1, v1, k1), e1) in i_edges:
                        logging.debug(('u1, v1, k1, e1: ', u1, v1, k1, e1))
                        self.remove_edge(u1, v1, k1)
                        i_edges.remove(((u1, v1, k1), e1))

            else:
                for ((u1, v1, k1), e1) in i_edges:
                    logging.debug(('scoreANDs u1, v1, k1, e1: ', u1, v1, k1, e1))
                    for ((u2, v2, k2), e2) in o_edges:
                        logging.debug(('u2, v2, k2, e2: ', u2, v2, k2, e2))

                        if self.nodes[v2]['type'] != 'OR':
                            logging.debug(('not an OR node... something bad happened...'))

                        self.nodes[v2]['scores'].append(self.nodes[a]['exploit_rule_score'])
                        logging.debug(('added score to child OR node: ', self.nodes[v2]))
                        # logging.debug(('making new edge: ', (u1, v2)))
                        if not v1:  # we're a root
                            self.remove_edge(u2, v2, k2)
                            o_edges.remove(((u2, v2, k2), e2))
                        elif not u2:  # we're a sink
                            self.remove_edge(u1, v1, k1)
                            o_edges.remove(((u1, v1), e1))
                        elif v1 == u2:
                            k = self.add_edge(u1, v2)
                            if e1: self[u1][v2][k].update(e1)
                            if e2: self[u1][v2][k].update(e2)
                            logging.debug(('making new edge: ', (u1, v2, k, self[u1][v2][k])))

                            self.remove_edge(u1, v1, k1)
                            i_edges.remove(((u1, v1, k1), e1))
                            self.remove_edge(u2, v2, k2)
                            o_edges.remove(((u2, v2, k2), e2))
                        else:
                            logging.debug(('ScoreANDs***** I Shouldnt be here *********'))

    def merge_two_dicts(x, y):
        # used when coalescing edge data
        #  https://stackoverflow.com/questions/38987/how-do-i-merge-two-dictionaries-in-a-single-expression
        # might need something smarter if 2+ edges are scored
        z = x.copy()  # start with x's keys and values
        z.update(y)  # modifies z with y's keys and values & returns None
        return z

    def coalesceANDnodes(self):
        andNodes = [n for n in self.nodes() if self.nodes[n]['type'] == 'AND' and self.nodes[n]['toCoalesce']]
        logging.debug(('andNodes to coalesce: ', andNodes))

        for a in andNodes:
            i_edges = [((u, v, k), e) for u, v, k, e in self.in_edges(a, keys=True, data=True)]
            o_edges = [((u, v, k), e) for u, v, k, e in self.out_edges(a, keys=True, data=True)]
            logging.debug(('a in out: ', a, i_edges, o_edges))
            if not i_edges or not o_edges:  # we're at root
                if not i_edges and not o_edges:
                    logging.debug(('coalesceANDnodes !!!!!!!!!! Isolated Node !!!!!!!!!!!!!!'))
                if not i_edges:
                    for ((u2, v2, k2), e2) in o_edges:
                        logging.debug(('u2, v2, k2, e2: ', u2, v2, k2, e2))
                        self.remove_edge(u2, v2, k2)
                        o_edges.remove(((u2, v2, k2), e2))
                if not o_edges:
                    for ((u1, v1, k1), e1) in i_edges:
                        logging.debug(('u1, v1, k1, e1: ', u1, v1, k1, e1))
                        self.remove_edge(u1, v1, k1)
                        i_edges.remove(((u1, v1, k1), e1))

            else:
                for ((u1, v1, k1), e1) in i_edges:
                    logging.debug(('u1, v1, k1, e1: ', u1, v1, k1, e1))
                    for ((u2, v2, k2), e2) in o_edges:
                        logging.debug(('u2, v2, k2, e2: ', u2, v2, k2, e2))
                        if not u1:  # we're a root
                            # logging.debug(('making new edge: ', (u1, v2)))
                            logging.debug(('coalesceAND - couldnt find v1 - are we a root?', v1))
                            self.remove_edge(u2, v2, k2)
                            o_edges.remove(((u2, v2, k2), e2))

                        elif not v2:  # we're a sink
                            logging.debug(('coalesceAND - couldnt find u1 - are we a sink?', u2, v2))
                            self.remove_edge(u1, v1, k1)
                            i_edges.remove(((u1, v1, k1), e1))

                        elif v1 == u2:

                            k = self.add_edge(u1, v2)
                            if e1: self[u1][v2][k].update(e1)
                            if e2: self[u1][v2][k].update(e2)
                            logging.debug(('making new edge: ', (u1, v2, k, self[u1][v2][k])))

                            self.remove_edge(u1, v1, k1)
                            i_edges.remove(((u1, v1, k1), e1))
                            self.remove_edge(u2, v2, k2)
                            o_edges.remove(((u2, v2, k2), e2))
                logging.debug(('i+o edges: ', i_edges, o_edges, i_edges + o_edges))

    def coalesceORnodes(self):
        orNodes = [n for n in self.nodes() if self.nodes[n]['type'] == 'OR' and len(self.nodes[n]['scores']) == 0]
        logging.debug(('Found ornodes ot coalesce: ', orNodes))
        loop_count = 1
        edgeTrash = set()
        while len(orNodes) > 0:
            logging.debug(('starting loop : ', loop_count))
            logging.debug(('known OR nodes: ', self.getORnodes()))
            logging.debug(('myOR nodes: ', orNodes))
            o = orNodes[0]
            logging.debug((self.nodes[o]))

            i_edges = [((u, v, k), e) for u, v, k, e in self.in_edges(o, keys=True, data=True)]
            o_edges = [((u, v, k), e) for u, v, k, e in self.out_edges(o, keys=True, data=True)]
            logging.debug(('coalesceORnodes o in V out: ', o, i_edges, o_edges))

            edgeTrash = set()

            if not i_edges or not o_edges:  # we're at root or sink
                if not i_edges and not o_edges:
                    logging.debug(('coalesceORnodes !!!!!!!!!! Isolated Node !!!!!!!!!!!!!!'))
                elif not i_edges:  # root
                    for ((u2, v2, k2), e2) in o_edges:
                        logging.debug(('iedges: ', i_edges))
                        logging.debug(('o, u2, v2, k2, e2: ', o, u2, v2, k2, e2))
                        self.remove_edge(u2, v2, k2)
                        o_edges.remove(((u2, v2, k2), e2))
                        edgeTrash.add((u2, v2, k2))
                        logging.debug(('edgeTrash: ', edgeTrash))
                elif not o_edges:  # sink
                    for ((u1, v1, k1), e1) in i_edges:
                        logging.debug(('oedges: ', o_edges))
                        logging.debug(('u1, v1 , k, e1: ', u1, v1, k1, e1))
                        self.remove_edge(u1, v1, k1)
                        i_edges.remove(((u1, v1, k1), e1))
            else:
                for ((u1, v1, k1), e1) in i_edges:
                    logging.debug(('u1, v1, k,  e1: ', u1, v1, k1, *e1))
                    for ((u2, v2, k2), e2) in o_edges:
                        logging.debug(('u2, v2, k2, e2: ', u2, v2, k2, e2))
                        if u1 and v2:  # all good
                            k = self.add_edge(u1, v2)
                            if e1: self[u1][v2][k].update(e1)
                            if e2: self[u1][v2][k].update(e2)
                            logging.debug(('making new edge: ', (u1, v2, k, self[u1][v2][k])))

                            edgeTrash.add((u1, v1, k1))
                            logging.debug(('edgeTrash: ', edgeTrash))

                        if not u1:  # we're a root
                            edgeTrash.add(((u2, v2, k2), e2))
                            logging.debug(('edgeTrash: ', edgeTrash))
                            logging.debug(('Root - nothing above to remove'))

                        elif not v2:  # we're a sink
                            edgeTrash.add(((u1, v1, k1), e1))
                            logging.debug(('Take out the trash: ', edgeTrash))
                            logging.debug(('Sink - nothing below to remove'))

                logging.debug(('coalesceORnodes i+o edges: ', i_edges, o_edges, i_edges + o_edges))
            self.remove_nodes_from(list(nx.isolates(self)))
            orNodes = [n for n in self.nodes() if self.nodes[n]['type'] == 'OR' and len(self.nodes[n]['scores']) == 0]
            logging.debug(('coalesceORnodes ', self.getORnodes()))
            logging.debug((orNodes))
            for o in orNodes:
                logging.debug((self.nodes[o]))
            self.plot2(outfilename=self.name + '_005_0_coalesceOrs.' + str(loop_count) + '.png')

            self.remove_edges_from(edgeTrash)
            edgeTrash.clear()
            loop_count += 1

    def pruneLEAFS(self):
        leafs = self.getLEAFnodes()
        self.remove_nodes_from(leafs)

    def setOrigin(self):
        logging.debug(('tgraph root node: ', self.origin))
        if not self.origin:
            roots = set()
            self.origin = '0'
            for n in self.getLEAFnodes():
                # logging.debug(('node n has preds: ', n, list(self.predecessors(n))))
                # logging.debug(('node n has inbound edges, in_degree:  ', n, self.in_degree(n)))
                logging.debug(('node n has attribute: ', self.nodes[n]['label']))
                if 'attackerLocated' in self.nodes[n]['label']:
                    roots.add(n)
                    logging.debug(('adding root', n, roots))
            o_edges = [((u, v, k), e) for u, v, k, e in self.out_edges(roots, keys=True, data=True)]
            for r in roots:
                for ((u2, v2, k2), e2) in o_edges:
                    logging.debug(('Adding to new root: u2, v2, k2, e2: ', u2, v2, k2, e2))
                    self.add_edge(self.origin, v2, k2, *e2)

            # [self.add_edge('0', n) for n in roots]

            # logging.debug(('found roots', roots, ' count: ', len(roots)))
            if len(roots) != 1: logging.debug(('weird, should i only using 1st root node: ', roots))
            self.nodes[self.origin]['type'] = 'ROOT'

            logging.debug(('tgraph root node: ', self.origin))

    def setEdgeScore(self, u, v, k, score):

        self[u][v][k]['score'] = score
        self[u][v][k]['weight'] = score
        self[u][v][k]['label'] = round(score, 2)

    def setEdgeScores(self, **kwargs):
        for n in self.nodes():
            self.nodes[n]['succs_sum'] = 0
            self.nodes[n]['succs_count'] = 0
            self.nodes[n]['preds_sum'] = 0
            self.nodes[n]['preds_count'] = 0
            i_edges = [((u, v, k), e) for u, v, k, e in self.in_edges(n, keys=True, data=True)]
            o_edges = [((u, v, k), e) for u, v, k, e in self.out_edges(n, keys=True, data=True)]

            for (u, v, k), e in i_edges:
                if 'score' not in self[u][v][k].keys():
                    self[u][v][k]['score'] = None
                if self[u][v][k]['score']:
                    self.nodes[n]['preds_sum'] += self[u][v][k]['score']
                self.nodes[n]['preds_count'] += 1

            for (u, v, k), e in o_edges:
                if 'score' not in self[u][v][k].keys():
                    self[u][v][k]['score'] = None
                if self[u][v][k]['score']:
                    self.nodes[n]['succs_sum'] += self[u][v][k]['score']
                self.nodes[n]['succs_count'] += 1

            denom = self.nodes[n]['succs_sum'] + self.nodes[n]['preds_sum']
            self.setEdgeScore(n, n, self.getSelfEdge(n), self.nodes[n]['preds_sum'])
            logging.debug(("sums: node[{}] outsum[{}] insum[{}] denom[{}] selfedge[{}]".format(
                n, self.nodes[n]['succs_sum'], self.nodes[n]['preds_sum'], denom,
                self[n][n][self.getSelfEdge(n)]['score'])))

    def setEdgeWeights(self, **kwargs):

        # set edge weights as fraction of sum_succs
        for n in self.nodes():
            denom = self.nodes[n]['succs_sum'] + self.nodes[n]['preds_sum']
            logging.debug(
                ('sums: ', n, self.nodes[n]['succs_sum'], self.nodes[n]['preds_sum'], denom, self.getSelfEdge(n)))
            if denom != 0:
                # i_edges = [((u, v, k), e) for u, v, k, e in self.in_edges(n, keys=True, data=True)]
                o_edges = [((u, v, k), e) for u, v, k, e in self.out_edges(n, keys=True, data=True)]

                for (u, v, k), e in o_edges:
                    if self[u][v][k]['score']:
                        self[u][v][k]['weight'] = self[u][v][k]['score'] / denom
                        self[u][v][k]['label'] = round(self[u][v][k]['score'] / denom, 2)
                # set self edge weight
                self.setEdgeScore(n, n, self.getSelfEdge(n), self.nodes[n]['preds_sum'] / denom)

    def getSelfEdge(self, n):
        # assuming each node only has one selfloop
        # so making this singleton
        if not self.has_edge(n, n):
            k = self.add_edge(n, n)
            return k
        elif self.number_of_edges(n, n) != 1:
            logging.debug(('too many selfloop edges!'))
        else:
            return 0  # default key

    def getReducedGraph(self, *args, **kwargs):
        """Returns the AG with coealesced edges


        """
        # tgraph = tgraph
        tgraph = deepcopy(self)

        # logging.debug(('tgraph root node: ', tgraph.has_node('0')))
        tgraph.setOrigin()
        # logging.debug(('tgraph root node: ', tgraph.has_node('0')))
        tgraph.plot2(outfilename=self.name + '_000.6_addOrigin.png')

        # 1. set AND node exploit score
        #    either default value of AND text or CVSS lookup
        tgraph.setANDscores()
        tgraph.plot2(outfilename=self.name + '_001_setANDscores.png')

        # 2. remove LEAF nodes after scores applied
        tgraph.pruneLEAFS()
        logging.debug(('Removing dead nodes: ', list(nx.isolates(tgraph))))
        tgraph.remove_nodes_from(list(nx.isolates(tgraph)))
        tgraph.plot2(outfilename=self.name + '_002_pruneLEAFs.png')

        # 3. Join edges passing through this and (multi-hop, no exploit)
        tgraph.coalesceANDnodes()
        logging.debug(('Removing dead nodes: ', list(nx.isolates(tgraph))))
        tgraph.remove_nodes_from(list(nx.isolates(tgraph)))
        tgraph.plot2(outfilename=self.name + '_003_coalesceANDs.png')

        # 4. push AND exploit_score down to child or score dicts
        tgraph.scoreANDs()
        logging.debug(('Removing dead nodes: ', list(nx.isolates(tgraph))))
        tgraph.remove_nodes_from(list(nx.isolates(tgraph)))
        tgraph.plot2(outfilename=self.name + '_004_scoreANDs.png')

        # 5. remove or nodes with empty score dict
        tgraph.coalesceORnodes()
        logging.debug(('Removing dead nodes: ', list(nx.isolates(tgraph))))
        tgraph.remove_nodes_from(list(nx.isolates(tgraph)))
        tgraph.plot2(outfilename=self.name + '_005_coalesceORs.png')

        # # 6. add root note for entry handle  # # logging.debug(('tgraph
        # root node: ', tgraph.has_node('0')))  # tgraph.setOrigin()  # #
        # logging.debug(('tgraph root node: ', tgraph.has_node('0')))  #
        # tgraph.plot2(outfilename=self.name + '_006_addOrigin.png')

        return tgraph

    def scoreTGraph(self, *args, **kwargs):

        # 6.5 add edge scores
        # breaking off to support different weighting strategies
        self.setEdgeScores()
        self.plot2(outfilename=self.name + '_006_scoreEdges.png')

    def weighTGraph(self, *args, **kwargs):
        # 7. add edge weights
        self.setEdgeWeights()
        self.plot2(outfilename=self.name + '_007_weighEdges.png')



    def getTransMatrix(self, *args, **kwargs):

        # tgraph = tgraph
        tgraph = deepcopy(self)

        # logging.debug(('tgraph root node: ', tgraph.has_node('0')))
        tgraph.setOrigin()
        # logging.debug(('tgraph root node: ', tgraph.has_node('0')))
        tgraph.plot2(outfilename=self.name + '_000.6_addOrigin.png')

        # 1. set AND node exploit score
        #    either default value of AND text or CVSS lookup
        tgraph.setANDscores()
        tgraph.plot2(outfilename=self.name + '_001_setANDscores.png')

        # 2. remove LEAF nodes after scores applied
        tgraph.pruneLEAFS()
        logging.debug(('Removing dead nodes: ', list(nx.isolates(tgraph))))
        tgraph.remove_nodes_from(list(nx.isolates(tgraph)))
        tgraph.plot2(outfilename=self.name + '_002_pruneLEAFs.png')

        # 3. Join edges passing through this and (multi-hop, no exploit)
        tgraph.coalesceANDnodes()
        logging.debug(('Removing dead nodes: ', list(nx.isolates(tgraph))))
        tgraph.remove_nodes_from(list(nx.isolates(tgraph)))
        tgraph.plot2(outfilename=self.name + '_003_coalesceANDs.png')

        # 4. push AND exploit_score down to child or score dicts
        tgraph.scoreANDs()
        logging.debug(('Removing dead nodes: ', list(nx.isolates(tgraph))))
        tgraph.remove_nodes_from(list(nx.isolates(tgraph)))
        tgraph.plot2(outfilename=self.name + '_004_scoreANDs.png')

        # 5. remove or nodes with empty score dict
        tgraph.coalesceORnodes()
        logging.debug(('Removing dead nodes: ', list(nx.isolates(tgraph))))
        tgraph.remove_nodes_from(list(nx.isolates(tgraph)))
        tgraph.plot2(outfilename=self.name + '_005_coalesceORs.png')

        # # 6. add root note for entry handle
        # # logging.debug(('tgraph root node: ', tgraph.has_node('0')))
        # tgraph.setOrigin()
        # # logging.debug(('tgraph root node: ', tgraph.has_node('0')))
        # tgraph.plot2(outfilename=self.name + '_006_addOrigin.png')

        # 6.5 add edge scores
        # breaking off to support different weighting strategies
        tgraph.setEdgeScores()
        tgraph.plot2(outfilename=self.name + '_006_scoreEdges.png')

        # 7. add edge weights
        tgraph.setEdgeWeights()
        tgraph.plot2(outfilename=self.name + '_007_weighEdges.png')

        # for n in tgraph.nodes():
        #     logging.debug((tgraph.nodes[n]))

        # orNodes = tgraph.getORnodes()
        # logging.debug(('or nodes before: ', orNodes))
        # for n in orNodes:
        #     # logging.debug(('set or node: ', n, type(n)))
        #     tgraph.setORscore(n)
        #     logging.debug((tgraph.nodes[n]))
        # logging.debug(('or nodes after: ', orNodes))

        if tgraph.origin:
            tgraph.remove_node(tgraph.origin)

        tmatrix, nodelist = tgraph.convertTMatrix()



        # logging.debug((type(tmatrix)))
        # tmatrix.setdiag(1)
        # logging.debug((tmatrix.todense()))
        # logging.debug(('nodes: ', tgraph.nodes()))

        # for n in tgraph.nodes():
        #     logging.debug((tgraph[n]))
        # tm_data = nx.adjacency_data(tgraph)
        # for k in tm_data.keys():
        #     logging.debug((k, tm_data[k]))

        # outfile = 'test.csv'
        # if 'MatrixFile' in kwargs.keys():
        #     outfile = kwargs['MatrixFile']
        # print(outfile)
        # # logging.debug(('header type: ', type(tgraph.node_list), tgraph.node_list))
        # logging.debug(('header type: ', type(tgraph.getNodeList()), tgraph.getNodeList()))
        # self.writeTmatrix(header=nodelist, tmatrix=tmatrix, filename=outfile)

        return tgraph, tmatrix, nodelist

    def getNodeList(self, includeSource=False):
        """
        Orders current nodes for writing tmatrix
        Currently just getting sources in the front and sinks at the end... may need to be smarter about this
        :return: ordered nodelist
        """

        node_list = []
        source = None
        sink = None
        transit = {}

        # self.nodes[n]['preds_sum'] = 0

        # tvs_ = [(n, v) for n, v in tgraph.nodes(data=True)]
        tvs_ = [(n, v) for n, v in self.nodes(data=True)]
        for (n, v) in tvs_:

            # set sinks sources
            if self.origin:
                source = self.origin
            elif self.in_degree(n) == 1:
                source = n
            if self.target:
                sink = self.target
            elif self.out_degree(n) == 0:
                sink = n

            # if self.in_degree(n) != 1 and self.out_degree(n) != 0: transit[n] = v
            if n not in (sink, source): transit[n] = v

        # build node list for tmatrix header
        if includeSource:
            node_list.append(source) # origin makes tmatrix non-invertible
        tmp = list(transit.keys())
        for n in range(len(tmp)):
            a = max([int(i) for i in tmp])
            # logging.debug(('added a to nodelist', a, type(str(a)), node_list))
            node_list.append(str(a))
            tmp.remove(str(a))
        if sink:
            node_list.append(sink)
        logging.debug(('added sink to nodelist', sink, node_list, self.nodes(), len(node_list), len(self.nodes())))
        # assert (len(node_list) == len(self.nodes()))

        return node_list

    def convertTMatrix(self):
        """
        transforms graph for writing to disk, adding nodes header, setting weights, etc
        :return:
        """

        nodelist = self.getNodeList()

        logging.debug(('len(node_list) == len(tgraph.nodes())', len(self.getNodeList()), ' == ', len(self.nodes())))

        tmatrix = nx.adjacency_matrix(self, nodelist)

        # logging.debug((tmatrix))
        logging.debug((tmatrix.todense()))

        return tmatrix, nodelist

        # logging.debug(('node | in_degree | out_degree: ', n, ' | ', tgraph.in_degree(n), ' | ', tgraph.out_degree(n)))
        # logging.debug(('tgraph', n, v))

    def writeTmatrix(self, header=None, tmatrix=None, filename=None):
        # logging.debug(('header: ', filename, header, tmatrix.todense()))
        # logging.debug(('Types tmatrix, dense: ', type(tmatrix), type(tmatrix.todense())))

        # filename = self.inputDir + '/' + self.outfileName + '.csv'
        if not filename:
            filename = self.outputDir + '/' + self.name + '.csv'
        logging.info(('Writing transition matrix to: ', filename))
        pandas.DataFrame(tmatrix.todense()).round(decimals=2).to_csv(filename, header=header, index=False)

    @staticmethod
    def printHelp():
        print('<usage> genTransMatrix.py inputdir outputfile customScoresDir, {opts}')
        print('options: ',
              'PLOT_INTERMEDIATE_GRAPHS=True'
              )

if __name__ == '__main__':
    if len(sys.argv) != 4:
        AttackGraph.printHelp()
        # logging.debug(('<usage> genTransMatrix.py inputdir outputfile customScoresDir opts'))
        sys.exit()

    AttackGraph.printHelp()
    inputDir = sys.argv[1]
    outfileName = sys.argv[2]
    scriptsDir = sys.argv[3]
    matrixFileName = inputDir + '/' + sys.argv[2] + '.csv'
    name = sys.argv[2]

    A = AttackGraph(inputDir=inputDir, scriptsDir=scriptsDir)
    A.name = name

    A.plot2(outfilename=name + '_001_orig.png')
    tgraph = deepcopy(A)

    tmatrix = A.getTransMatrix(tgraph, inputDir=inputDir, outfileName=outfileName)

