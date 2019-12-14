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

  def convert_cves_to_json(self):
    cve_raw = pathlib.Path(CVE_LOCAL_FILE_NAME_RAW)
    cve_json = pathlib.Path(CVE_LOCAL_FILE_PROCESSED)
    if not cve_json.exists():
      logging.debug('writing cve_json: %s' % CVE_LOCAL_FILE_PROCESSED)
      cve_df = pd.read_csv(cve_raw, sep=',', quotechar='"', header=2,
                           skiprows=range(3, 10), encoding="ISO-8859-1")
      cve_df.to_csv(CVE_LOCAL_FILE_PROCESSED)
    else:
      logging.debug('cve_json already exists: %s' % CVE_LOCAL_FILE_PROCESSED)


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
    json_dfs = []
    outfile = pathlib.Path(NVD_LOCAL_FILE)
    cve_dfs = []
    # cve_df = pd.DataFrame()
    if not outfile.exists() and not overwrite_if_exists:
      logging.debug('writing nist_nvd to json: %s...' % NVD_LOCAL_FILE)
      for gzip_file in self.nvd_file_list:
        year_df = pd.read_json(SEP.join((DOWNLOAD_DIR, gzip_file)))
        cve_dfs.append(json_normalize(year_df['CVE_Items']))
      cve_df = pd.concat(cve_dfs, sort=False)
      for col in cve_df.columns:
        print(col)
      cve_df = cve_df.set_index(['cve.CVE_data_meta.ID'])
      cve_df.to_json(NVD_LOCAL_FILE)
    else:
      logging.debug('found nvd_nist file at: %s' % NVD_LOCAL_FILE)

  def read_nvd_from_json(self, *args, **kwargs):
    date_cols = ['publishedDate', 'lastModifiedDate']
    return pd.read_json(NVD_LOCAL_FILE, convert_dates=date_cols)


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
  cve.convert_cves_to_json()

  nvd = nist_nvd()
  nvd.get_nvd_from_nist()
  nvd.write_nvd_to_json()
  nvd_df = nvd.read_nvd_from_json()
  nvd_df.describe()

