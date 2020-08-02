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

"""Run struct_secmet."""

from py_mulval import configs
from py_mulval import flags
from py_mulval import mulpy
from py_mulval import py_mulval

# from py_mulval import vm_util

# from py_mulval.windows_packages import iperf3


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

FLAGS = flags.FLAGS

BENCHMARK_NAME = 'struct_secmet'
BENCHMARK_CONFIG = """
struct_secmet:
  description: Run struct metrics
  flags:
#     input_file: single_host_1.P
#     rule: local_exploit_rules.P
#     models_dir: /opt/projects/diss/py-mulval/data/models 
#     rules_dir: /opt/projects/diss/py-mulval/data/rules 
#     data_dir: /opt/projects/diss/py-mulval/data
#     secmet_ag_path: AttackGraph.dot
#     # output_dir: 
  # vm_groups:
# """

CITATION_SHORT = 'cite_short'
CITATION_FULL = 'long citation'

# flags.DEFINE_string('cite_key', None, CITATION_SHORT)
# flags.DEFINE_string('cite_long', None, CITATION_FULL)
# flags.DEFINE_string('ag_path', None, 'use this attack graph')


def GetConfig(user_config):
  return configs.LoadConfig(BENCHMARK_CONFIG, user_config, BENCHMARK_NAME)


def Prepare(benchmark_spec):

  if not benchmark_spec.attack_graph:
    ag = bmutil.get_attack_graph()
    benchmark_spec.attack_graph = ag


def Run(benchmark_spec):
  """Collect Structural Metrics for an attack graph

  Args:
    benchmark_spec: The benchmark specification. Contains all data that is
        required to run the benchmark.

  Returns:
    A list of sample.Sample objects with the benchmark results.
  """

  # vms = benchmark_spec.vms
  results = []

  def _RunTest():
    """Runs the tests depending on what is enabled.
  
    Args:
      sending_vm: The vm that will initiate the stream.
      receiving_vm: The vm that will act as server.
    """
    # if vm_util.ShouldRunOnExternalIpAddress():
    if FLAGS.run_udp:
      results.extend('heh')

      _RunTest()  # _RunTest(vms[1], vms[0])

    return results


def Cleanup(unused_benchmark_spec):
  pass
