import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from pandas.io.json import json_normalize

import argparse
import gzip
import os
import json
# import ijson
import platform
import pathlib
import sys
import logging
import re
import urllib.request
from itertools import chain
from jinja2 import Template

import jupyter_core

# from owlready2 import *
# from stix2 import *
# from stix2 import FileSystemSource as fs
# from stix2 import Filter
# from stix2.utils import get_type_from_id


SEP = os.path.sep

sys.path.append('..')

# MulVal Data Loading
# BASE_DIR = '/opt/projects/diss/jupyter_nbs/mine'
BASE_DIR = '/opt/projects/diss/py-mulval'
DATA_DIR = SEP.join((BASE_DIR, 'data'))
WORKING_DIR = SEP.join((DATA_DIR, 'test_004_nvd'))
DOWNLOAD_DIR = SEP.join((WORKING_DIR, 'downloads'))
PROCESSED_DIR = SEP.join((WORKING_DIR, 'processed'))

# logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG)
# LOG_FILE = SEP.join((WORKING_DIR, '000-nvd_explore.log'))
# logging.basicConfig(
#     level=logging.DEBUG,
#     format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
#     handlers=[
#         logging.FileHandler("{0}/{1}.log".format(WORKING_DIR, '000-nvd_explore')),
#         logging.StreamHandler()
#     ])


CVE_REMOTE_URL = 'http://cve.mitre.org/data/downloads/allitems.csv'
CVE_LOCAL_FILE_NAME_RAW = 'CVE_MITRE_SET.csv'
CVE_LOCAL_FILE_NAME = 'CVE_MITRE_SET.json'
CVE_LOCAL_FILE_RAW = SEP.join((DOWNLOAD_DIR, CVE_LOCAL_FILE_NAME_RAW))
CVE_LOCAL_FILE_PROCESSED = SEP.join((PROCESSED_DIR, CVE_LOCAL_FILE_NAME))

NVD_SCHEMA_REMOTE_URL = 'https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema'

NVD_REMOTE_JSON_FEED_LIST = 'https://nvd.nist.gov/vuln/data-feeds#JSON_FEED'
NVD_REMOTE_JSON_FEED_BASE = 'https://nvd.nist.gov/feeds/json/cve/1.1'
NVD_REMOTE_JSON_FILE_PATTERN = r'(nvdcve-1\.1-[0-9]*?\.json\.gz)'  # only pull yearly files
NVD_LOCAL_FILE_NAME = 'nist_nvd.json'
NVD_LOCAL_FILE = SEP.join((PROCESSED_DIR, NVD_LOCAL_FILE_NAME))


# NVD_REMOTE_JSON_FILE_PATTERN = r'(nvdcve-1\.1-[a-zA-Z0-9]*?\.json\.gz)' #  pull modified and recent as well


class mitre_cve(object):
  def __init__(self, *args, **kwargs):
    super(mitre_cve, self)

  def get_cves_from_mitre(self):
    cve_raw = pathlib.Path(CVE_LOCAL_FILE_RAW)

    if not cve_raw.exists():
      logging.debug('downloading cve_raw: %s' % CVE_LOCAL_FILE_RAW)
      urllib.request.urlretrieve(CVE_REMOTE_URL, CVE_LOCAL_FILE_RAW)
    else:
      logging.debug('cve_raw already exists: %s' % CVE_LOCAL_FILE_RAW)

  def write_cves_to_json(self, overwrite_if_exists=False):
    cve_raw = pathlib.Path(CVE_LOCAL_FILE_NAME_RAW)
    cve_json = pathlib.Path(CVE_LOCAL_FILE_PROCESSED)
    if not cve_json.exists() or overwrite_if_exists:
      logging.debug('writing cve_json: %s' % CVE_LOCAL_FILE_PROCESSED)
      cve_df = pd.read_csv(cve_raw, sep=',', quotechar='"', header=2,
                           skiprows=range(3, 10), encoding="ISO-8859-1")
      cve_df.to_json(CVE_LOCAL_FILE_PROCESSED, orient='table')
    else:
      logging.debug('cve_json already exists: %s' % CVE_LOCAL_FILE_PROCESSED)

  def read_cves_from_json(self, *args, **kwargs):
    date_cols = ['publishedDate', 'lastModifiedDate']

    # return pd.read_json(CVE_LOCAL_FILE_PROCESSED, convert_dates=date_cols,
    #                     orient='table')
    return pd.read_json(CVE_LOCAL_FILE_PROCESSED, orient='table')


class nist_nvd(object):

  def __init__(self, *args, **kwargs):
    super(nist_nvd, self)

    self.nvd_file_list = list()

  def get_nvd_from_nist(self):

    #  download NVD yearly feeds if they don't exist
    feed_list = urllib.request.urlopen(NVD_REMOTE_JSON_FEED_LIST)
    response = feed_list.read()
    for filename in re.findall(NVD_REMOTE_JSON_FILE_PATTERN, str(response)):
      self.nvd_file_list.append(filename)
      outfile_name = SEP.join(((DOWNLOAD_DIR, filename)))
      outfile = pathlib.Path(outfile_name)
      if not outfile.exists():
        logging.debug('downloading nvd_file: %s' % outfile_name)
        urllib.request.urlretrieve(
            '/'.join((NVD_REMOTE_JSON_FEED_BASE, filename)), outfile)
      else:
        logging.debug('found nvd file %s, skipping download...' % outfile)

    logging.debug(self.nvd_file_list)

  def write_nvd_to_json(self, overwrite_if_exists=False):
    outfile = pathlib.Path(NVD_LOCAL_FILE)
    cve_dfs = []
    date_cols = ['publishedDate',
                 'lastModifiedDate']
    bool_cols = ['impact.baseMetricV2.acInsufInfo',
                 'impact.baseMetricV2.obtainAllPrivilege',
                 'impact.baseMetricV2.obtainUserPrivilege',
                 'impact.baseMetricV2.obtainOtherPrivilege',
                 'impact.baseMetricV2.userInteractionRequired']
    category_cols = [
      'cve.data_type',
      'cve.data_format',
      'cve.data_version',
      'cve.CVE_data_meta.ASSIGNER',
      'configurations.CVE_data_version',
      'impact.baseMetricV3.cvssV3.version',
      #        'impact.baseMetricV3.cvssV3.vectorString',
      'impact.baseMetricV3.cvssV3.attackVector',
      'impact.baseMetricV3.cvssV3.attackComplexity',
      'impact.baseMetricV3.cvssV3.privilegesRequired',
      'impact.baseMetricV3.cvssV3.userInteraction',
      'impact.baseMetricV3.cvssV3.scope',
      'impact.baseMetricV3.cvssV3.confidentialityImpact',
      'impact.baseMetricV3.cvssV3.integrityImpact',
      'impact.baseMetricV3.cvssV3.availabilityImpact',
      'impact.baseMetricV3.cvssV3.baseSeverity',
      'impact.baseMetricV2.cvssV2.version',
      #        'impact.baseMetricV2.cvssV2.vectorString',
      'impact.baseMetricV2.cvssV2.accessVector',
      'impact.baseMetricV2.cvssV2.accessComplexity',
      'impact.baseMetricV2.cvssV2.authentication',
      'impact.baseMetricV2.cvssV2.confidentialityImpact',
      'impact.baseMetricV2.cvssV2.integrityImpact',
      'impact.baseMetricV2.cvssV2.availabilityImpact',
      'impact.baseMetricV2.severity',
    ]

    if not outfile.exists() or overwrite_if_exists:
      logging.debug('writing nist_nvd to json: %s...' % NVD_LOCAL_FILE)
      for gzip_file in self.nvd_file_list:
        year_df = pd.read_json(SEP.join((DOWNLOAD_DIR, gzip_file)))
        cve_dfs.append(json_normalize(year_df['CVE_Items']))
      cve_df = pd.concat(cve_dfs, sort=False)
      for col in cve_df.columns:
        print(col)
      cve_df = cve_df.set_index(['cve.CVE_data_meta.ID'])
      cve_df[bool_cols] = cve_df[bool_cols].astype(bool)
      cve_df[category_cols] = cve_df[category_cols].astype('category')
      # 'table="orient" can not yet read timezone ' "data")
      # cve_df[date_cols] = cve_df[date_cols].apply(pd.to_datetime)
      print(cve_df.info())
      cve_df.to_json(NVD_LOCAL_FILE, orient='table')
    else:
      logging.debug('found nvd_nist file at: %s' % NVD_LOCAL_FILE)

  def read_nvd_from_json(self, *args, **kwargs):
    date_cols = ['publishedDate', 'lastModifiedDate']

    # raise NotImplementedError('table="orient" can not yet read timezone ' "data")
    return pd.read_json(NVD_LOCAL_FILE, convert_dates=date_cols, orient='table')
    # return pd.read_json(NVD_LOCAL_FILE, orient='table')


def setup():
  dirs = [WORKING_DIR, DOWNLOAD_DIR, PROCESSED_DIR]

  logging.basicConfig(
      level=logging.DEBUG,
      format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
      handlers=[
        logging.FileHandler(
            "{0}/{1}.log".format(WORKING_DIR, '000-nvd_explore')),
        logging.StreamHandler()
      ])

  for dir in dirs:
    # logging.debug(('creating working directory: %s') % (WORKING_DIR))
    path = pathlib.Path(dir)
    if not path.exists():
      logging.debug('%s doesnt exist, creating...' % path)
      path.mkdir(parents=True, exist_ok=True)
    else:
      logging.debug('%s already exists, skipping...' % path)


if __name__ == "__main__":
  # def Main():

  setup()  # configure logging, create dirs, ...

  os.chdir(WORKING_DIR)

  cve = mitre_cve()
  cve.get_cves_from_mitre()
  cve.write_cves_to_json()
  # cve.write_cves_to_json(overwrite_if_exists=True)
  cve_df = cve.read_cves_from_json()
  print(cve_df.describe())
  print(cve_df.info())
  print(cve_df.head())

  nvd = nist_nvd()
  nvd.get_nvd_from_nist()
  # nvd.write_nvd_to_json(overwrite_if_exists=True)
  nvd.write_nvd_to_json()
  nvd_df = nvd.read_nvd_from_json()

  v2_cols = {'impact.baseMetricV2.cvssV2.version': 'v2.version',
             'impact.baseMetricV2.cvssV2.vectorString': 'v2.vectorString',
             'impact.baseMetricV2.cvssV2.accessVector': 'v2.accessVector',
             'impact.baseMetricV2.cvssV2.accessComplexity': 'v2.accessComplexity',
             'impact.baseMetricV2.cvssV2.authentication': 'v2.authentication',
             'impact.baseMetricV2.cvssV2.confidentialityImpact': 'v2.confidentialityImpact',
             'impact.baseMetricV2.cvssV2.integrityImpact': 'v2.integrityImpact',
             'impact.baseMetricV2.cvssV2.availabilityImpact': 'v2.availabilityImpact',
             'impact.baseMetricV2.cvssV2.baseScore': 'v2.baseScore',
             'impact.baseMetricV2.severity': 'v2.severity',
             'impact.baseMetricV2.exploitabilityScore': 'v2,exploitabilityScore',
             'impact.baseMetricV2.impactScore': 'v2.impactScore',
             'impact.baseMetricV2.acInsufInfo': 'v2.acInsufInfo',
             'impact.baseMetricV2.obtainAllPrivilege': 'v2.obtainAllPrivilege',
             'impact.baseMetricV2.obtainUserPrivilege': 'v2.obtainUserPrivilege',
             'impact.baseMetricV2.obtainOtherPrivilege': 'v2.obtainOtherPrivilege',
             'impact.baseMetricV2.userInteractionRequired': 'v2.userInteractionRequired`'}

  v3_cols = {'impact.baseMetricV3.cvssV3.version': 'v3.version',
             'impact.baseMetricV3.cvssV3.vectorString': 'v3.vectorString',
             'impact.baseMetricV3.cvssV3.attackVector': 'v3.attackVector',
             'impact.baseMetricV3.cvssV3.attackComplexity': 'v3.attackComplexity',
             'impact.baseMetricV3.cvssV3.privilegesRequired': 'v3.privilegesRequired',
             'impact.baseMetricV3.cvssV3.userInteraction': 'v3.userInteraction',
             'impact.baseMetricV3.cvssV3.scope': 'v3.scope',
             'impact.baseMetricV3.cvssV3.confidentialityImpact': 'v3.confidentialityImpact',
             'impact.baseMetricV3.cvssV3.integrityImpact': 'v3.integrityImpact',
             'impact.baseMetricV3.cvssV3.availabilityImpact': 'v3.availabilityImpact',
             'impact.baseMetricV3.cvssV3.baseScore': 'v3.baseScore',
             'impact.baseMetricV3.cvssV3.baseSeverity': 'v3.baseSeverity',
             'impact.baseMetricV3.exploitabilityScore': 'v3.exploitabilityScore',
             'impact.baseMetricV3.impactScore': 'v3.impactScore', }

  common_cols = ['publishedDate', 'lastModifiedDate', 'cve.data_type',
                 'cve.data_format',
                 'cve.data_version', 'cve.CVE_data_meta.ASSIGNER',
                 'cve.problemtype.problemtype_data',
                 'cve.references.reference_data',
                 'cve.description.description_data',
                 'configurations.CVE_data_version',
                 'configurations.nodes', ]

  # make easy names
  nvd_df = nvd_df.rename(columns={**v2_cols, **v3_cols})

  print(nvd_df.describe())
  print(nvd_df.info())
  print(nvd_df.head())
