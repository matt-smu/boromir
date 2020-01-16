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
"""Classes that verify and transform metric configuration input.

See py_mulval/configs/__init__.py for more information about
configuration files.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function


from py_mulval import errors
from py_mulval import flag_util
from py_mulval.configs import option_decoders
from py_mulval.configs import spec


import contextlib
import logging
import os
import six




class _VmGroupSpec(spec.BaseSpec):
  """Configurable options of a VM group.

  Attributes:
    cloud: string. Cloud provider of the VMs in this group.
    disk_count: int. Number of data disks to attach to each VM in this group.
    disk_spec: BaseDiskSpec. Configuration for all data disks to be attached to
        VMs in this group.
    os_type: string. OS type of the VMs in this group.
    static_vms: None or list of StaticVmSpecs. Configuration for all static VMs
        in this group.
    vm_count: int. Number of VMs in this group, including static VMs and
        provisioned VMs.
    vm_spec: BaseVmSpec. Configuration for provisioned VMs in this group.
    placement_group_name: string. Name of placement group
        that VM group belongs to.
    cidr: subnet each vm in this group belongs to
  """

  def __init__(self, component_full_name, flag_values=None, **kwargs):
    super(_VmGroupSpec, self).__init__(
        component_full_name, flag_values=flag_values, **kwargs)
    ignore_package_requirements = (getattr(flag_values,
                                           'ignore_package_requirements', True)
                                   if flag_values else True)
    providers.LoadProvider(self.cloud, ignore_package_requirements)
    if self.disk_spec:
      disk_config = getattr(self.disk_spec, self.cloud, None)
      if disk_config is None:
        raise errors.Config.MissingOption(
            '{0}.cloud is "{1}", but {0}.disk_spec does not contain a '
            'configuration for "{1}".'.format(component_full_name, self.cloud))
      disk_spec_class = disk.GetDiskSpecClass(self.cloud)
      self.disk_spec = disk_spec_class(
          '{0}.disk_spec.{1}'.format(component_full_name, self.cloud),
          flag_values=flag_values,
          **disk_config)
    vm_config = getattr(self.vm_spec, self.cloud, None)
    if vm_config is None:
      raise errors.Config.MissingOption(
          '{0}.cloud is "{1}", but {0}.vm_spec does not contain a '
          'configuration for "{1}".'.format(component_full_name, self.cloud))
    vm_spec_class = virtual_machine.GetVmSpecClass(self.cloud)
    self.vm_spec = vm_spec_class(
        '{0}.vm_spec.{1}'.format(component_full_name, self.cloud),
        flag_values=flag_values,
        **vm_config)

  @classmethod
  def _GetOptionDecoderConstructions(cls):
    """Gets decoder classes and constructor args for each configurable option.

    Returns:
      dict. Maps option name string to a (ConfigOptionDecoder class, dict) pair.
      The pair specifies a decoder class and its __init__() keyword arguments
      to construct in order to decode the named option.
    """
    result = super(_VmGroupSpec, cls)._GetOptionDecoderConstructions()
    result.update({
        'cloud': (option_decoders.EnumDecoder, {
            'valid_values': providers.VALID_CLOUDS
        }),
        'disk_count': (option_decoders.IntDecoder, {
            'default': _DEFAULT_DISK_COUNT,
            'min': 0,
            'none_ok': True
        }),
        'disk_spec': (option_decoders.PerCloudConfigDecoder, {
            'default': None,
            'none_ok': True
        }),
        'os_type': (option_decoders.EnumDecoder, {
            'valid_values': os_types.ALL
        }),
        'static_vms': (_StaticVmListDecoder, {}),
        'vm_count': (option_decoders.IntDecoder, {
            'default': _DEFAULT_VM_COUNT,
            'min': 0
        }),
        'cidr': (option_decoders.StringDecoder, {
            'default': None
        }),
        'vm_spec': (option_decoders.PerCloudConfigDecoder, {}),
        'placement_group_name': (option_decoders.StringDecoder, {
            'default': None,
            'none_ok': True
        }),
    })
    return result

  @classmethod
  def _ApplyFlags(cls, config_values, flag_values):
    """Modifies config options based on runtime flag values.

    Can be overridden by derived classes to add support for specific flags.

    Args:
      config_values: dict mapping config option names to provided values. May
          be modified by this function.
      flag_values: flags.FlagValues. Runtime flags that may override the
          provided config values.
    """
    super(_VmGroupSpec, cls)._ApplyFlags(config_values, flag_values)
    if flag_values['cloud'].present or 'cloud' not in config_values:
      config_values['cloud'] = flag_values.cloud
    if flag_values['os_type'].present or 'os_type' not in config_values:
      config_values['os_type'] = flag_values.os_type
    if 'vm_count' in config_values and config_values['vm_count'] is None:
      config_values['vm_count'] = flag_values.num_vms


class _VmGroupsDecoder(option_decoders.TypeVerifier):
  """Validates the vm_groups dictionary of a benchmark config object."""

  def __init__(self, **kwargs):
    super(_VmGroupsDecoder, self).__init__(valid_types=(dict,), **kwargs)

  def Decode(self, value, component_full_name, flag_values):
    """Verifies vm_groups dictionary of a benchmark config object.

    Args:
      value: dict mapping VM group name string to the corresponding VM group
          config dict.
      component_full_name: string. Fully qualified name of the configurable
          component containing the config option.
      flag_values: flags.FlagValues. Runtime flag values to be propagated to
          BaseSpec constructors.

    Returns:
      dict mapping VM group name string to _VmGroupSpec.

    Raises:
      errors.Config.InvalidValue upon invalid input value.
    """
    vm_group_configs = super(_VmGroupsDecoder, self).Decode(
        value, component_full_name, flag_values)
    result = {}
    for vm_group_name, vm_group_config in six.iteritems(vm_group_configs):
      result[vm_group_name] = _VmGroupSpec(
          '{0}.{1}'.format(
              self._GetOptionFullName(component_full_name), vm_group_name),
          flag_values=flag_values,
          **vm_group_config)
    return result


class _VmGroupSpecDecoder(option_decoders.TypeVerifier):
  """Validates a single VmGroupSpec dictionary."""

  def __init__(self, **kwargs):
    super(_VmGroupSpecDecoder, self).__init__(valid_types=(dict,), **kwargs)

  def Decode(self, value, component_full_name, flag_values):
    """Verifies vm_groups dictionary of a benchmark config object.

    Args:
      value: dict corresonding to a VM group config.
      component_full_name: string. Fully qualified name of the configurable
          component containing the config option.
      flag_values: flags.FlagValues. Runtime flag values to be propagated to
          BaseSpec constructors.

    Returns:
      dict a _VmGroupSpec.

    Raises:
      errors.Config.InvalidValue upon invalid input value.
    """
    vm_group_config = super(_VmGroupSpecDecoder, self).Decode(
        value, component_full_name, flag_values)
    return _VmGroupSpec(
        self._GetOptionFullName(component_full_name),
        flag_values=flag_values,
        **vm_group_config)



class BenchmarkConfigSpec(spec.BaseSpec):
  """Configurable options of a benchmark run.

  Attributes:perfkitbenchmarker
    description: None or string. Description of the benchmark to run.
    name: Optional. The name of the benchmark
    flags: dict. Values to use for each flag while executing the
        benchmark.
    vm_groups: dict mapping VM group name string to _VmGroupSpec. Configurable
        options for each VM group used by the benchmark.
  """

  def __init__(self, component_full_name, expected_os_types=None, **kwargs):
    """Initializes a BenchmarkConfigSpec.

    Args:
      component_full_name: string. Fully qualified name of the benchmark config
          dict within the config file.
      expected_os_types: Optional series of strings from os_types.ALL.
      **kwargs: Keyword arguments for the BaseSpec constructor.

    Raises:
      errors.Config.InvalidValue: If expected_os_types is provided and any of
          the VM groups are configured with an OS type that is not included.
    """
    super(BenchmarkConfigSpec, self).__init__(component_full_name, **kwargs)
    if expected_os_types is not None:
      mismatched_os_types = []
      for group_name, group_spec in sorted(six.iteritems(self.vm_groups)):
        if group_spec.os_type not in expected_os_types:
          mismatched_os_types.append('{0}.vm_groups[{1}].os_type: {2}'.format(
              component_full_name, repr(group_name), repr(group_spec.os_type)))
      if mismatched_os_types:
        raise errors.Config.InvalidValue(
            'VM groups in {0} may only have the following OS types: {1}. The '
            'following VM group options are invalid:{2}{3}'.format(
                component_full_name, ', '.join(
                    repr(os_type) for os_type in expected_os_types), os.linesep,
                os.linesep.join(mismatched_os_types)))

  @classmethod
  def _GetOptionDecoderConstructions(cls):
    """Gets decoder classes and constructor args for each configurable option.

    Can be overridden by derived classes to add options or impose additional
    requirements on existing options.

    Returns:
      dict. Maps option name string to a (ConfigOptionDecoder class, dict) pair.
      The pair specifies a decoder class and its __init__() keyword arguments
      to construct in order to decode the named option.
    """
    result = super(BenchmarkConfigSpec, cls)._GetOptionDecoderConstructions()
    result.update({
        'description': (option_decoders.StringDecoder, {
            'default': None
        }),
        'name': (option_decoders.StringDecoder, {
            'default': None
        }),
        'flags': (option_decoders.TypeVerifier, {
            'default': None,
            'none_ok': True,
            'valid_types': (dict,)
        }),
        'vm_groups': (_VmGroupsDecoder, {
            'default': {}
        }),
        # 'placement_group_specs': (_PlacementGroupSpecsDecoder, {
        #     'default': {}
        # }),
        # 'spark_service': (_SparkServiceDecoder, {
        #     'default': None
        # }),
        # 'container_cluster': (_ContainerClusterSpecDecoder, {
        #     'default': None
        # }),
        # 'container_registry': (_ContainerRegistryDecoder, {
        #     'default': None
        # }),
        # 'container_specs': (_ContainerSpecsDecoder, {
        #     'default': None
        # }),
        # 'dpb_service': (_DpbServiceDecoder, {
        #     'default': None
        # }),
        # 'relational_db': (_RelationalDbDecoder, {
        #     'default': None
        # }),
        # 'tpu_groups': (_TpuGroupsDecoder, {
        #     'default': {}
        # }),
        # 'edw_service': (_EdwServiceDecoder, {
        #     'default': None
        # }),
        # 'cloud_redis': (_CloudRedisDecoder, {
        #     'default': None
        # }),
        # 'app_groups': (_AppGroupsDecoder, {
        #     'default': {}
        # }),
    })
    return result

  def _DecodeAndInit(self, component_full_name, config, decoders, flag_values):
    """Initializes spec attributes from provided config option values.

    Args:
      component_full_name: string. Fully qualified name of the configurable
          component containing the config options.
      config: dict mapping option name string to option value.
      decoders: OrderedDict mapping option name string to ConfigOptionDecoder.
      flag_values: flags.FlagValues. Runtime flags that may override provided
          config option values. These flags have already been applied to the
          current config, but they may be passed to the decoders for propagation
          to deeper spec constructors.
    """
    # Decode benchmark-specific flags first and use them while decoding the
    # rest of the BenchmarkConfigSpec's options.
    decoders = decoders.copy()
    self.flags = config.get('flags')
    with self.RedirectFlags(flag_values):
      super(BenchmarkConfigSpec, self)._DecodeAndInit(
          component_full_name, config, decoders, flag_values)

  @contextlib.contextmanager
  def RedirectFlags(self, flag_values):
    """Redirects flag reads and writes to the benchmark-specific flags object.

    Args:
      flag_values: flags.FlagValues object. Within the enclosed code block,
          reads and writes to this object are redirected to self.flags.
    Yields:
      context manager that redirects flag reads and writes.
    """
    with flag_util.OverrideFlags(flag_values, self.flags):
      yield
