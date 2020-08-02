# Copyright 2018 PerfKitBenchmarker Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Run Mean Time To Failure benchmark."""
import os
# import pathlib
# import networkx
# from networkx.readwrite import json_graph
# import json

import os
SEP = os.path.sep
import sys

from py_mulval import configs
from py_mulval import data
from py_mulval import flags
# from py_mulval import genTransMatrix
from py_mulval import attack_graph
# from py_mulval import mulpy
# from py_mulval import py_mulval
from py_mulval import sample
from py_mulval import vm_util
from py_mulval import benchmark_utils as bmutil

from py_mulval.metrics.ag_metrics import mttf
import py_mulval.metrics
FLAGS = flags.FLAGS

BENCHMARK_NAME = 'mttf'
BENCHMARK_CONFIG = """
mttf:
  description: Run mttf metric
  flags:
    # input_file: single_host_1.P
    # input_file: h2v1s5.P
    # rule: local_exploit_rules.P
    ## set pointers below to change default locations for a test
    # models_dir: /opt/projects/diss/py-mulval/data/models
    # secmet_fg_path: /opt/projects/diss/py-mulval/data/facts 
    # secmet_fg_name: mulval_facts.single_host_1.json
    # rules_dir: /opt/projects/diss/py-mulval/data/rules 
    # data_dir: /opt/projects/diss/py-mulval/data
    # secmet_ag_path: AttackGraph.dot
    # secmet_map_scores: cvss2time
    # output_dir: 
  # vm_groups:
"""

def GetConfig(user_config):
  return configs.LoadConfig(BENCHMARK_CONFIG, user_config, BENCHMARK_NAME)


def Prepare(benchmark_spec):
  """ Prepare the benchmark
  For all benchmarks, set the fact_graph in the spec
  For AG metrics, set the attack_greph in the spec

  :param benchmark_spec:
  :return:
  """



  if not benchmark_spec.attack_graph:
    ag = bmutil.get_attack_graph()
    benchmark_spec.attack_graph = ag

def Run(benchmark_spec):
  """Collect MTTF Metrics for an attack graph

  Args:
    benchmark_spec: The benchmark specification. Contains all data that is
        required to run the benchmark.

  Returns:
    A list of sample.Sample objects with the benchmark results.
  """
  results = []

  metric = mttf.mttf_metric()
  metric.ag = benchmark_spec.attack_graph
  value, metadata = metric.calculate()
  results.append(
    sample.Sample(metric.METRIC_NAME, value,
                  metric.METRIC_UNIT, metadata))

  return results


def Cleanup(unused_benchmark_spec):
  pass
