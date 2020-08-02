#!/usr/bin/env python
import logging
import os
import json
import random
import re
import sys
import warnings
import itertools
from copy import deepcopy
from pathlib import Path

import pathlib

import MySQLdb
import matplotlib
import matplotlib.pyplot as plt
import networkx as nx
import pandas
import scipy
import yaml

from networkx.drawing.nx_agraph import read_dot
from networkx.drawing import nx_agraph
import pygraphviz

from py_mulval import flags

warnings.simplefilter('ignore', scipy.sparse.SparseEfficiencyWarning)

FACTS_FILE = 'mulval_facts.json'

FLAGS = flags.FLAGS




class FactGraph(nx.MultiDiGraph):
  """
  Class for making input graphs from MulVal loaded facts.
  """

  def __init__(self, *args, **kwargs):
    # logging.debug((self.nodes()))

    self.scriptsDir = '.'  # os.cwd()
    if 'scriptsDir' in kwargs.keys():
      self.scriptsDir = kwargs['scriptsDir']
      logging.debug(('scriptsDir: ', self.scriptsDir))

    self.inputDir = '.'  # os.cwd()
    if 'inputDir' in kwargs.keys():
      self.inputDir = kwargs['inputDir']
      logging.debug(('inputDir: ', self.inputDir))

    self.outputDir = self.inputDir  # os.cwd()
    if 'outputDir' in kwargs.keys():
      self.outputDir = kwargs['outputDir']
      logging.debug(('output: ', self.outputDir))

    self.data = None
    self.facts_dict = {}

    # parsesd facts here
    self.hosts = set()
    self.links = set() # set elements are 2-tuples (src, dest) hosts
    self.edgeDatas = {} # edges datas are keyed by (src, dst, port, protocol)
    self.vulns = set()
    self.host2vulns = {}

    super(FactGraph, self).__init__(self.data)

    # add fields not included in dot file
    self.__updateFG()

  # def write_dot(self, dot_path):
  #   nx.drawing.nx_agraph.write_dot(self, dot_path)

  def to_dots(self):
    return json.dumps(str(nx.nx_agraph.to_agraph(self)))

  def load_dot_file(self, dot_file_path):
    logging.info('loading dot file: %s', dot_file_path)
    self.data = read_dot(dot_file_path)
    super(FactGraph, self).__init__(self.data)
    self.__updateFG()

  def load_json_file(self, json_file_path):
    """loads a json dict of mulval facts and updates graph"""
    logging.info('loading json file: %s', json_file_path)
    if pathlib.Path(json_file_path).exists():
      with open(json_file_path, 'r') as infile:
        self.facts_dict = json.load(infile)
      self.parseFactsFromDict()
    else:
      logging.error('json file doesnt exist: '.format(json_file_path))

  def load_json_string(self, json_string):
    """loads a json dict of mulval facts and updates graph"""
    logging.info('loading json file: %s', json_string)
    self.facts_dict = json.loads(json_string)
    self.parseFactsFromDict()

  def load_dot_string(self, dot_string):
    logging.info('loading dot string: %s', dot_string)
    # self.data = dot_string
    self.data = nx_agraph.from_agraph(pygraphviz.AGraph(dot_string))
    super(FactGraph, self).__init__(self.data)
    self.__updateFG()

  def to_dots(self):
    # return json.dumps(str(nx.nx_agraph.to_agraph(self)))
    return str(nx.nx_agraph.to_agraph(self))

  def write_dot_file(self, out_file_path):
    """Writes current state to graphviz dot file
    :param out_file_path: fq file name
    :return:
    """
    nx.nx_agraph.write_dot(self, out_file_path)

  def __updateFG(self):
    """ Updates graph with current data
    :return:
    """
    # update host nodes
    node_props = {} # add host attributes here
    node_props['shape'] = 'box'
    node_props['type'] = 'HOST'
    node_props['color'] = 'blue'
    node_props['s'] = 's'
    for host in self.hosts:
      if host not in self.nodes.keys():
        self.add_node(host, **node_props)

    # update edges
    edge_props = {}
    # edge_props['label'] = 'box'
    # edge_props['type'] = 'HOST'
    # edge_props['color'] = 'blue'
    # print(self.links)
    self.expandLinks() # explodes 'ANY' refs in links
    for (src, dst) in self.links:
      self.add_edge(src, dst, **edge_props)

  def expandLinks(self):
    """replaces 'ALL' in self.links with all known hosts"""
    expandedlinks = set()
    discardLinks = set()
    for (src, dst) in self.links:
      # print('src: {}, dst: {}'.format(src, dst))
      if src == 'ANY' and dst == 'ANY':
        logging.error('ANY-ANY link found')
        return
      elif src== 'ANY':
        exploded = list(itertools.zip_longest(self.hosts, [dst], fillvalue=dst))
        discardLinks.add((src,dst))
        expandedlinks.update(exploded)
        # print(exploded)
      elif dst == 'ANY':
        exploded = list(itertools.zip_longest([src], self.hosts, fillvalue=src))
        discardLinks.add((src, dst))
        expandedlinks.update(exploded)
        # print(exploded)
    # print('---old---\n',  self.links)
    self.links.difference_update(discardLinks)
    self.links.update(expandedlinks)
    # print('---new---\n',  self.links)

  def parseFactsFromDict(self):
    """Parses facts_dict items dumped after mulval run"""

    # get known hosts
    self.parseHacl()

    super(FactGraph, self).__init__(self.data)
    self.__updateFG()


  def parseHacl(self):
    """Parses hacl/5 facts and updates known hosts and links
    :return:
    """
    if 'hacl' in self.facts_dict.keys() and type(self.facts_dict['hacl']) is list and self.facts_dict['hacl']:
      for hacl in self.facts_dict['hacl'][0]:
        if len(hacl) != 4:
          logging.error('hacl/4 not found... continuing')
          logging.error(hacl)
          continue
        src = hacl[0] if type(hacl[0]) not in (tuple, list) else 'ANY'
        dst = hacl[1] if type(hacl[1]) not in (tuple, list) else 'ANY'
        protocol = hacl[2] if type(hacl[2]) not in (tuple, list) else 'ANY'
        port = hacl[3] if type(hacl[3]) not in (tuple, list) else 'ANY'

        # add new hosts
        logging.debug('adding {}, {} to known hosts'.format(src, dst))
        if src not in ('ANY', None):
          self.hosts.add(src)
        if dst not in ('ANY', None):
          self.hosts.add(dst)

        # add edges
        if src is not None and dst is not None:
          if src == 'ANY' and dst == 'ANY':
            logging.info('ANY to ANY link found in hacl/4, ignoring...')
          else:
            self.links.add((src, dst))
            self.edgeDatas[(src, dst, port, protocol)] = {}

    if None in self.hosts: # probably a cleaner way to do this
      self.hosts.discard(None)

  def plot2(self, *args, **kwargs):
    if not self.PLOT_INTERMEDIATE_GRAPHS:
      # bail if we don't want noisy output
      return
    if 'outfilename' in kwargs:
      outfilename = kwargs.get("outfilename")
    else:
      outfilename = 'test.png'

    A = nx.nx_agraph.to_agraph(self)
    A.layout('dot',
             args='-Nfontsize=10 -Nwidth=".2" -Nheight=".2" -Nmargin=0 '
                  '-Gfontsize=8')
    A.draw(self.outputDir + '/' + outfilename)
    plt.show()