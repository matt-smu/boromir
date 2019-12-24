

from absl import app
from absl import flags

import log_util

FLAGS = flags.FLAGS


"""
Usage: graph_gen.sh [-r|--rule rulefile]
            [-a|--additional additional_rulefile]
    [-c|--constraint constraint_file]
    [-g|--goal goal]
    [-d|--dynamic dynamic_file]
    [-p]
    [-s|--sat]
    [-t|--t trace_option]
    [-tr|--trim]
    [-v|--visualize [--arclabel] [--reverse]]
            [--cvss]
        [-h|--help]
        [attack_graph_options]
        input_file
"""
flags.DEFINE_multi_string('rule', None, 'add rule file(s).', short_name='r')
flags.DEFINE_multi_string('additional', None, 'add additional rule file(s).', short_name='a')
flags.DEFINE_multi_string('constraint', None, 'add constraint file(s).', short_name='c')
flags.DEFINE_multi_string('goal', None, 'add goal(s).', short_name='g')
flags.DEFINE_multi_string('dynamic', None, 'add dynamic file(s).', short_name='d')
flags.DEFINE_bool('visualize', True, 'create viz (implies csv output).', short_name='V')
flags.DEFINE_bool('write_csv', True, 'Write CSV output', short_name='l')
flags.DEFINE_string('input_file', None, 'input file', short_name='i')
flags.DEFINE_bool('arclabel', True, 'arclabel')
flags.DEFINE_bool('reverse', True, 'reverse')
flags.DEFINE_bool('simple', True, 'simple')
flags.DEFINE_bool('metric', False, 'metric')
flags.DEFINE_bool('sat', True, 'SAT', short_name='s')
flags.DEFINE_bool('satgui', True, 'SAT GUI', short_name='sg')
flags.DEFINE_string('trace', 'completeTrace2', 'trace option', short_name='t')
flags.DEFINE_bool('trim', True, 'trim', short_name='tr')
flags.DEFINE_bool('trimdom', True, 'trimdom', short_name='td')
flags.DEFINE_bool('cvss', True, 'cvss')
flags.DEFINE_bool('ma', True, 'metric artifacts')


def Main():
  print('The value of myflag is %s' % FLAGS)


if __name__ == '__main__':
  app.run(Main)
