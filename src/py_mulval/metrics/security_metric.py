from uuid import uuid4
import pathlib
import logging
import pygraphviz
from pathlib import Path
import sys
import os
SEP = os.path.sep
from py_mulval import errors
from py_mulval import flag_util

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

    self.fg = FactGraph() # input system model common to all metrics
    self.loadFactsGraph()
    super().__init__()

  def loadFactsGraph(self):

    if FLAGS.secmet_fg_dot and pathlib.Path(FLAGS.secmet_fg_dot).exists():
      self.fg = FactGraph.from_agraph(pygraphviz.AGraph(FLAGS.secmet_fg_dot))
    else:
      fg_path = FLAGS.secmet_fg_path
      fg_name = FLAGS.secmet_fg_name
      outfileName = os.path.splitext(fg_name)[0] + '.dot'  # '{facts}.{json}'
      outfile = SEP.join((fg_path, outfileName))
      if pathlib.Path(outfile).exists(): # maybe we wrote it already
        logging.info('Found fact file at default path: {}'.format(outfile))
        self.fg.load_dot_file(outfile)

        # self.fg = FactGraph()
        # FLAGS[secmet_fg_dot] = outfile
      else:
        if pathlib.Path(SEP.join((fg_path, fg_name))).exists():
          logging.info('couldnt find fact graph dot, loading default {}'.format(SEP.join((fg_path, fg_name))))
          self.fg.load_json_file(SEP.join((fg_path, fg_name)))
          self.fg.name = os.path.splitext(fg_name)[0]
          self.fg.write_dot(outfile) # make a new outfile for next time
          # FLAGS[secmet_fg_dot] = outfile



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

