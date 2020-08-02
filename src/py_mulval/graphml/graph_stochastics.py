# from py_mulval import log_util
import numpy as np
from absl import flags
from pyxsb import *

"""Tests for py_mulval.attack_graph."""

# from py_mulval import pkb  # pylint: disable=unused-import # noqa
# from py_mulval import static_virtual_machine as static_vm
# from py_mulval.linux_benchmarks import iperf_benchmark
# from py_mulval.providers.gcp import util

FLAGS = flags.FLAGS

SEP = os.path.sep

""" Random acts on grpahs
"""


def get_fmatrix(Q, *args, **kwargs):
  """ Gets the fundamental matrix from a Q transition matrix. Uses faster method 2 unless told otherwise.
  :param Q:
  :param args:
  :param kwargs:
  :return:
  """
  __get_fmatrix_2(Q)


def __get_fmatrix_1(Q):
  I = numpy.identity(Q.shape[0])
  N = numpy.linalg.inv(I - Q)
  o = numpy.ones(Q.shape[0])
  numpy.dot(N, o)


def __get_fmatrix_2(Q):
  I = numpy.identity(Q.shape[0])
  o = numpy.ones(Q.shape[0])
  numpy.linalg.solve(I - Q, o)


def sample_from_dist(dist='exp', *args, **kwargs):
  if dist == 'exp':
    if 'rate' in kwargs.keys() and kwargs['rate']:
      return sample_from_dist(*args, **kwargs)


def sample_from_dis_exponential(rate=.5):
  import random
  if rate == 0:
    return oo
  return random.expovariate(rate)


def sample_from_rate(rate):
  import random
  if rate == 0:
    return oo
  return random.expovariate(rate)


def simulate(x, nsteps):
  """Run the simulation."""
  for _ in range(nsteps - 1):
    # Which trials to update?
    upd = (0 < x) & (x < N - 1)
    # In which trials do births occur?
    birth = 1 * (np.random.rand(ntrials) <= a * x)
    # In which trials do deaths occur?
    death = 1 * (np.random.rand(ntrials) <= b * x)
    # We update the population size for all trials
    x[upd] += birth[upd] - death[upd]


def simulate_cmc(Q, time, warm_up):
  Q = list(Q)  # In case a matrix is input
  state_space = range(len(Q))  # Index the state space
  time_spent = {s: 0 for s in state_space}  # Set up a dictionary to keep track of time
  clock = 0  # Keep track of the clock
  current_state = 0  # First state
  while clock < time:
    # Sample the transitions
    sojourn_times = [sample_from_rate(rate) for rate in Q[current_state][:current_state]]
    sojourn_times += [oo]  # An infinite sojourn to the same state
    sojourn_times += [sample_from_rate(rate) for rate in Q[current_state][current_state + 1:]]

    # Identify the next state
    next_state = min(state_space, key=lambda x: sojourn_times[x])
    sojourn = sojourn_times[next_state]
    clock += sojourn
    if clock > warm_up:  # Keep track if past warm up time
      time_spent[current_state] += sojourn
    current_state = next_state  # Transition

  pi = [time_spent[state] / sum(time_spent.values()) for state in state_space]  # Calculate probabilities
  return pi

from py_mulval.attack_graph import AttackGraph
import networkx as nx

def AGMarkov(g):
  np.set_printoptions(suppress=True)
  ag = AttackGraph()
  ag.load_dot_file('/opt/projects/diss/py-mulval/data/mulval_ag/small_enterprise/AttackGraph.dot')
  ag.name = 'small_enterprise'
  ag.load_score_dict('/opt/projects/diss/py-mulval/src/py_mulval/data/secmet/scoreDict.yml')
  ag.PLOT_INTERMEDIATE_GRAPHS = False
  ag.map_scores = 'cvss2time'
  reduced_ag = ag.getReducedGraph()
  node_list = list(nx.topological_sort(reduced_ag))

  # reduced_ag = ag.getReducedGraph()
  normalize_scores_graph1(reduced_ag, weight='score')
  node_list = list(nx.topological_sort(reduced_ag))
  P_orig = nx.adjacency_matrix(reduced_ag, nodelist=node_list, weight='score_orig')
  P_normal = nx.adjacency_matrix(reduced_ag, nodelist=node_list, weight='weighted_score')

  ag.map_scores = 'cvss2time'
  reduced_ag = ag.getReducedGraph()
  P_mapped = nx.adjacency_matrix(reduced_ag, nodelist=node_list, weight='score')

  # print('CVSS weighted:\n', P_orig.todense())
  # print('CVSS weighted normalized:\n', P_normal.todense())
  # print(node_list, '<-node IDs\n')
  # print('CVSS mappped to arrival rates:\n', P_mapped.todense())


  steps = 2000
  state = np.zeros(len(node_list), dtype=int)
  state[0] = 2000
  print(state)

  return(MarkovChain(state, P_normal, 30))


# https://github.com/anthonymelson/portfolio/blob/32d920e67325501acec6f171ea7762135bd9d599/Comparing_Absorbing_and_Non_Absorbing_Markov_Chains.ipynb
def MarkovChain(state, transition, iterations):
  stateHistory = []
  stateTrack = [state]
  last_state = []
  i = 0
  length = [0]
  convergence = False

  while convergence == False and i < iterations:
    last_state = state
    state = np.dot(state, transition)
    stateTrack.append(list(state))
    i = i + 1
    length.append(i)

    # if all(last_state == state) == True:
    #   convergence = True

  return stateTrack, length, state
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
def PlotMarkov(stateTrack, length, state):
  labels = ['State %d' % i for i in range(len(state))]
  dims =(10.7, 7.27)
  fig, ax = plt.subplots(figsize=dims)
  plt.xlabel('Number of Transitions')
  plt.ylabel('Amount of Wieght in State')
  splot = pd.DataFrame(stateTrack, length, labels)
  sns.lineplot(ax=ax, data = splot, markers=True)


def normalize_scores_graph1(g, weight='score', strategy=None):
  """ makes cvss scores into probabilities according to [Abraham2014]
  add new edge label 'weighted_score' so return matrix isnt needed here
  this can be done in attack graph too (set edge scores)
  :param weight: the edge labels to normalize
  :return:
  """
  nodetally = {}
  # nodetally['nodes'] = {}
  nodelist = list(nx.topological_sort(g))
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

  q = nx.adjacency_matrix(g, nodelist, weight=NEW_EDGE_LABEL)  # print(nodelist, q.todense())  # return q
