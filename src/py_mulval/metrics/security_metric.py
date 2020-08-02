from uuid import uuid4
import pathlib
import logging
import pygraphviz
from pathlib import Path
import sys
import json
import os
SEP = os.path.sep
from py_mulval import errors
from py_mulval import flag_util
from py_mulval import benchmark_utils as bmutil
import networkx
import pprint
from py_mulval.mulval_fact_graph import FactGraph

from absl import flags
from absl import app


from py_mulval import import_util

FLAGS = flags.FLAGS

# These module vars should describe the metric and get included in the metadata
METRIC_NAME = None  # required for benchmark naming, should be unique
METRIC_UNIT = None
METRIC_SUMMARY = None
CITATION_SHORT = None
CITATION_FULL = None
USAGE = None


class BaseSecurityMetric(object):
  """Object representing a base security metric."""

  def __init__(self) -> None: # https://refactoring.guru/design-patterns/builder/python/example
    # Set instance properties to whatever they are down there
    current_module = sys.modules[self.__class__.__module__]
    self.METRIC_NAME = current_module.METRIC_NAME
    self.METRIC_UNIT = current_module.METRIC_UNIT
    self.USAGE = current_module.USAGE
    self.CITATION_SHORT = current_module.CITATION_SHORT
    self.CITATION_FULL = current_module.CITATION_FULL
    self.METRIC_SUMMARY = current_module.METRIC_SUMMARY

    self.random_seed = FLAGS.secmet_random_seed
    self.fg = None
    self.fg_path = None
    self.score_strategy = None

    # FactGraph() # input system model common to all metrics
    # self.loadFactsGraph()
    super().__init__()

    self.metric_properties = {'random_seed': self.random_seed,
                              'cvss_based': None,
                              'weight': 'score',
                              }

  def loadFactsGraphDot(self, fg_dot_path):
    self.fg = FactGraph.from_agraph(pygraphviz.AGraph(FLAGS.secmet_fg_dot))
    # return 0

  def loadFactGraphJson(self, fg_json_path):
    self.fg.load_json_file(fg_json_path)



  #
  # def loadFactsGraph(self):
  #   if self.fg_path and pathlib.Path(fg_path).exists():
  #     self.fg = FactGraph.from_agraph(pygraphviz.AGraph(self.fg_path))
  #     return 0
  #
  #   if FLAGS.secmet_fg_dot and pathlib.Path(FLAGS.secmet_fg_dot).exists():
  #     self.fg = FactGraph.from_agraph(pygraphviz.AGraph(FLAGS.secmet_fg_dot))
  #     return 0
  #   elif FLAGS.input_file  and pathlib.Path(FLAGS.input_file).exists():
  #     fg_path = FLAGS.secmet_fg_path
  #     fg_name = FLAGS.secmet_fg_name
  #     outfileName = os.path.splitext(fg_name)[0] + '.dot'  # '{facts}.{json}'
  #     outfile = SEP.join((fg_path, outfileName))
  #     if pathlib.Path(outfile).exists(): # maybe we wrote it already
  #       logging.info('Found fact file at default path: {}'.format(outfile))
  #       return self.fg.load_dot_file(outfile)
  #
  #
  #       # self.fg = FactGraph()
  #       # FLAGS[secmet_fg_dot] = outfile
  #     else:
  #       if pathlib.Path(SEP.join((fg_path, fg_name))).exists():
  #         logging.info('couldnt find fact graph dot, loading default {}'.format(SEP.join((fg_path, fg_name))))
  #         self.fg.load_json_file(SEP.join((fg_path, fg_name)))
  #         self.fg.name = os.path.splitext(fg_name)[0]
  #         self.fg.write_dot(outfile) # make a new outfile for next time
  #         # FLAGS[secmet_fg_dot] = outfile
  #         return 0
  #   return -1



  def CheckPreReqs(self):
    pass

  def getMetaData(self):
    metadata = {  # The meta data defining the environment
        'metric_name': self.METRIC_NAME,
        'metric_unit': self.METRIC_UNIT,
        # 'metric_summary': self.METRIC_SUMMARY,
        'cite_key': self.CITATION_SHORT,
        # 'citation': self.CITATION_FULL,
        # 'metric_usage': self.USAGE,

        'input_model': self.fg
    }

    if not self.fg:
      self.fg = bmutil.get_fact_graph()

    if self.fg:
      metadata['facts_graph_orig'] = self.fg.to_dots()
      json_file_path = bmutil.get_fg_jsonfile_location()

      with open(json_file_path, 'r') as infile:
        self.facts_dict = json.load(infile)
      metadata['facts_json'] = self.facts_dict
    flags_sent = flag_util.GetProvidedCommandLineFlags()
    metadata.update(flags_sent)
    metadata['facts_graph'] = self.fg.to_dots() if self.fg else None
    return metadata

  def getUnique(self, slice=8):
    """ Gets a unique value for suffixes and such. @TODO seed this properly
    :param slice: The bits off the end of UUID4 needed
    :return: unique value
    """
    rd = random.Random()
    rd.seed(0)
    uuid.uuid4 = lambda: uuid.UUID(int=rd.getrandbits(128))
    return str(uuid.uuid4())[:slice]

  def calculate(self):
    pass

class AGBasedSecMet(BaseSecurityMetric):

  def __init__(self):
    super(AGBasedSecMet, self).__init__()


    self.ag = None
    # self.tgraph = None
    # self.tmatrix = None

  def getMetaData(self):
    # ag_metadata = {}.update(self.ag.getMetaData())
    # return super().getMetaData().update(ag_metadata)
    # print('-----ag_based_md called: ')#, len(metadata.keys()))
    metadata = super().getMetaData()
    # agmd = self.ag.getMetaData()
    if self.ag:
      metadata['attack_graph_orig'] = self.ag.to_dots()


    # agmd = self.ag.getMetaData()
    # print('-----ag_md: ', len(agmd.keys()))
    # metadata.update(agmd)
    # print('-----merged: ', len(metadata.keys()))

    return metadata


  def CheckPreReqs(self):
    if not self.ag:
      raise errors.Error('AG Metric called without an attack graph set')
    pass




  def normalize_scores(self, o, weight='score', strategy=None):
    if strategy == 'matrix_1':
      return self.normalize_scores_matrix1(o, weight=weight)
    else:
      return self.normalize_scores_graph1(o, weight=weight)

  def normalize_scores_matrix1(self, Q, weight='score', strategy=None):
    """ makes cvss scores into probabilities
    :param Q:
    :return:
    """
    f = Q.sum(axis=1)
    with np.errstate(divide='ignore', invalid='ignore'):
      Q = Q / f
    Q[np.isnan(Q)] = 0
    return Q

  def normalize_scores_graph1(self, g, weight='score', strategy=None):
    """ makes cvss scores into probabilities according to [Abraham2014]
    add new edge label 'weighted_score' so return matrix isnt needed here
    this can be done in attack graph too (set edge scores)
    :param weight: the edge labels to normalize
    :return:
    """

    if strategy is None or strategy == 'abr2014':
      nodetally = {}
      # nodetally['nodes'] = {}
      nodelist = list(networkx.topological_sort(g))
      NEW_EDGE_LABEL = 'weighted_score'


      for n in g.nodes():
        # only concerned with outbound probs in this weighting method
        nodetally[n] = {}
        # pprint.pprint(nodetally)

        nodetally[n]['succs_sum'] = 0
        nodetally[n]['succs_count'] = 0
        nodetally[n]['preds_sum'] = 0
        nodetally[n]['preds_count'] = 0

        # i_edges = [((u, v, k), e) for u, v, k, e in g.in_edges(n, keys=True, data=True)]
        o_edges = [((u, v, k), e) for u, v, k, e in g.out_edges(n, keys=True, data=True)]

        # for (u, v, k), e in i_edges:
        #   if weight not in g[u][v][k].keys():
        #     nodetally[u][v][k][weight] = None
        #   if g[u][v][k][weight] is not None:
        #     nodetally[n]['preds_sum'] += g[u][v][k][weight]
        #   nodetally[n]['preds_count'] += 1

        for (u, v, k), e in o_edges:
          if weight not in g[u][v][k].keys():
            nodetally[u][v][k][weight] = None
          if g[u][v][k][weight] is not None:
            nodetally[n]['succs_sum'] += g[u][v][k][weight]
          nodetally[n]['succs_count'] += 1

          denom = nodetally[n]['succs_sum']
          for (u, v, k), e in o_edges:
            if weight not in g[u][v][k].keys():
              nodetally[u][v][k][weight] = None
            if g[u][v][k][weight] is not None and g[u][v][k][weight] > 0:
              g[u][v][k]['weighted_score']= g[u][v][k][weight] / denom

        # if not self.score_strategy:
        #   denom = nodetally[n]['succs_sum'] + nodetally[n]['preds_sum']
          # self.setEdgeScore(n, n, self.getSelfEdge(n), self.nodes[n]['preds_sum'], self.nodes[n]['preds_sum'])
          # logging.debug((
          # "sums: node[{}] outsum[{}] insum[{}] denom[{}] selfedge[{}]".format(n, nodetally[n]['succs_sum'],
          # nodetally[n]['preds_sum'], denom))) #, nodetally[n][n][nodetally.getSelfEdge(n)]['score'])))
      # pprint.pprint(nodetally)
      q = networkx.adjacency_matrix(g, nodelist, weight=NEW_EDGE_LABEL)
      # print(nodelist, q.todense())
      # return q

      if strategy == 'abr2015':
        nodetally = {}
        # nodetally['nodes'] = {}
        nodelist = list(networkx.topological_sort(g))
        NEW_EDGE_LABEL = 'weighted_score'

        for n in g.nodes():
          # only concerned with outbound probs in this weighting method
          nodetally[n] = {}
          # pprint.pprint(nodetally)

          nodetally[n]['succs_sum'] = 0
          nodetally[n]['succs_count'] = 0
          nodetally[n]['preds_sum'] = 0
          nodetally[n]['preds_count'] = 0

          # i_edges = [((u, v, k), e) for u, v, k, e in g.in_edges(n, keys=True, data=True)]
          o_edges = [((u, v, k), e) for u, v, k, e in g.out_edges(n, keys=True, data=True)]

          # for (u, v, k), e in i_edges:
          #   if weight not in g[u][v][k].keys():
          #     nodetally[u][v][k][weight] = None
          #   if g[u][v][k][weight] is not None:
          #     nodetally[n]['preds_sum'] += g[u][v][k][weight]
          #   nodetally[n]['preds_count'] += 1

          for (u, v, k), e in o_edges:
            if weight not in g[u][v][k].keys():
              nodetally[u][v][k][weight] = None
            if g[u][v][k][weight] is not None:
              nodetally[n]['succs_sum'] += g[u][v][k][weight]
            nodetally[n]['succs_count'] += 1

            denom = nodetally[n]['succs_sum']
            for (u, v, k), e in o_edges:
              if weight not in g[u][v][k].keys():
                nodetally[u][v][k][weight] = None
              if g[u][v][k][weight] is not None and g[u][v][k][weight] > 0:
                g[u][v][k]['weighted_score'] = g[u][v][k][weight] / denom

          # if not self.score_strategy:  #   denom = nodetally[n]['succs_sum'] + nodetally[n]['preds_sum']  # self.setEdgeScore(n, n, self.getSelfEdge(n), self.nodes[n]['preds_sum'], self.nodes[n]['preds_sum'])  # logging.debug((  # "sums: node[{}] outsum[{}] insum[{}] denom[{}] selfedge[{}]".format(n, nodetally[n]['succs_sum'],  # nodetally[n]['preds_sum'], denom))) #, nodetally[n][n][nodetally.getSelfEdge(n)]['score'])))
        # pprint.pprint(nodetally)
        q = networkx.adjacency_matrix(g, nodelist, weight=NEW_EDGE_LABEL)  # print(nodelist, q.todense())  # return q



