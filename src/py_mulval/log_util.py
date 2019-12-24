import logging


DEBUG = 'debug'
INFO = 'info'
WARNING = 'warning'
ERROR = 'error'
LOG_LEVELS = {
    DEBUG: logging.DEBUG,
    INFO: logging.INFO,
    WARNING: logging.WARNING,
    ERROR: logging.ERROR}

def ConfigureLogging():
  logging.basicConfig(level=logging.DEBUG,
                      format="%(asctime)s [%(threadName)-12.12s] [%("
                             "levelname)-5.5s]  %("
                             "message)s", handlers=[
      logging.FileHandler("{0}/{1}.log".format('.', 'cat-dog')),
      logging.StreamHandler()])
