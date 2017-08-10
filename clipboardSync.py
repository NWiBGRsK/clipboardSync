"""
author: Volker Lehmann
version: 0.1@work
last modified: 2017-08-10
"""

import logging #for logging
import time 
import signal #for a graceful exit
import socket #for the network sync
import threading #for the network sync
import pyperclip #to have platform independent access to the clipboard
import json #to load config

# make sure we can exit the script gracefully without any annoying errors
__bExecuteMainLoop = True

def handler(signum, frame):
  #import pdb;pdb.set_trace()
  ###debug print("signal handler: signum is '%d' // frame.f_code is '%s'" % (signum, frame.f_code))
  global __bExecuteMainLoop
  __bExecuteMainLoop = False

signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)
#  
  
def getLogger(sName, sFileName):
  logger = logging.getLogger(sName)
  logger.setLevel(logging.DEBUG)
  ## log file
  fhLogfile = logging.FileHandler(sFileName)
  fhLogfile.setLevel(logging.DEBUG)
  ## stream handler for console output
  hStream = logging.StreamHandler()
  hStream.setLevel(logging.INFO)  
  #use this formatter for the log file
  formatterLogfile = logging.Formatter('%(asctime)s %(levelname)s (%(filename)s:%(lineno)d) %(message)s')
  fhLogfile.setFormatter(formatterLogfile)
  #use this formatter for console
  formatterConsole = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
  hStream.setFormatter(formatterConsole)
  # add the handlers to the logger
  #logger.addHandler(fhLogfile)
  logger.addHandler(hStream)
  return logger


class ClipboardSync:
  __logger = None
  __listOfClients = []
  __nPort = None
  __objSenderSocket = None
  __objReceiverSocket = None
  __sNewContent = None
  
  def __init__(self, nPort = 46994, logger = None):
    if logger == None:
      self.__logger = getLogger("ClipboardSync", __file__ + ".log")
    else:
      self.__logger = logger
    #
    if (nPort is None) or (type(nPort) is not int):
      raise("nPort is none or has the wrong type, please check!")
    else:
      self.__nPort = nPort
    
  def addClient(self, sClientIpAddress):
    if sClientIpAddress not in self.__listOfClients:
      self.__listOfClients.append(sClientIpAddress)
      
  def updateClients(self, sData):
    for sClientIpAddress in self.__listOfClients:
      try:
        self.__sendData(sClientIpAddress, sData)
      except Exception as ex:
        self.__logger.error("could not send data to client '%s'" % (sClientIpAddress), exc_info = ex)
      
  def __sendData(self, sClientIpAddress, sData):
    #check if there is already a sender socket and if not create one
    if (self.__objSenderSocket == None):
      #create a new UDP socket
      self.__objSenderSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
      #allow other sockets to bind this port
      self.__objSenderSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      #set timeout
      self.__objSenderSocket.settimeout(1.0)
    #  
    sendTo = (sClientIpAddress, self.__nPort)
    sent = self.__objSenderSocket.sendto(sData.encode("utf8"), sendTo)
    self.__logger.debug("sent '%d' bytes to client '%s'" % (sent, sClientIpAddress))

  def isNewContentAvailable(self):
    if self.__sNewContent is None:
      return False
    else:
      return True
      
  def getNewContent(self):
    sTmp = self.__sNewContent
    self.__sNewContent = None
    return sTmp
  
  def receiveDataLoop(self, sInputNetworkInterface = None):
    if self.__objReceiverSocket is None:
      try:
        #create a new UDP socket
        self.__objReceiverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        #allow other sockets to bind this port
        self.__objReceiverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #set timeout
        self.__objReceiverSocket.settimeout(3.0)
        #bind
        if (sInputNetworkInterface is not None) and (len(sInputNetworkInterface) >= 7): #len("1.1.1.1") == 7
          self.__objReceiverSocket.bind((sInputNetworkInterface, self.__nPort))
        else:
          self.__objReceiverSocket.bind((str(socket.INADDR_ANY), self.__nPort))
      except Exception as ex:
        self.__logger.error("could not create receiver socket", exc_info = ex)
        self.__objReceiverSocket = None
    #
    # start listener thread, if we were able to create a listening socket
    if self.__objReceiverSocket is not None:
      objCurrentThread = threading.currentThread()
      while getattr(objCurrentThread, "do_run", True):
        self.__receiveData()
    else:
      self.__logger.error("will not start receiver thread, because could not open listener socket")
  
  def __receiveData(self):
    if self.__objReceiverSocket is not None:
      try:
        (byUdpPayload, tupleClientAddress) = self.__objReceiverSocket.recvfrom(10240)
        sTmpNewContent = byUdpPayload.decode("utf8")
        self.__logger.debug("IP address is '%s' // len(byUdpPayload) = '%s' // len(decoded msg) is '%d'" % (str(tupleClientAddress), len(byUdpPayload), len(sTmpNewContent)))
        if (tupleClientAddress[0] in self.__listOfClients):
          self.__sNewContent = sTmpNewContent
        else:
          self.__logger.warning("received content from an IP address '%s', which is not in list of clients, will ignore the received content" % tupleClientAddress[0])
        #
      except socket.timeout:
        # nothing to it is expected, that the socket will timeout frequently
        pass
      except Exception as ex:
        self.__logger.error("could not receive data from socket", exc_info = ex)
    else:
      self.__logger.warning("could not receive data, because no receiver socket instance is available")
      #  
    #

    
if __name__ == "__main__":
  # init logger
  __logger = getLogger("ClipboardWin", __file__ + ".log")
  # load config
  sConfigFile = "clipboardSync.json"
  fhConfigFile = open(sConfigFile, "rt")
  dictConfig = json.load(fhConfigFile)
  __logger.debug(json.dumps(dictConfig, sort_keys = True, indent = 2))
  # init network sync class
  if "useThisUdpPortForNetworkCommunication" in dictConfig:
    objClipboardSync = ClipboardSync(dictConfig["useThisUdpPortForNetworkCommunication"], __logger)
  else:
    objClipboardSync = ClipboardSync(logger = __logger)
  #
  if "listClientIPsToSyncWith" in dictConfig:
    for sClientIpAddress in dictConfig["listClientIPsToSyncWith"]:
      __logger.info("adding '%s' to list of clients to sync with" % sClientIpAddress)
      objClipboardSync.addClient(sClientIpAddress)
      #
    #
  #
  # start receiver thread
  __logger.debug("starting receiver thread")
  if "localIpAddressOfInterfaceToListen" in dictConfig:
    sListenOnThisIpAddress = dictConfig["localIpAddressOfInterfaceToListen"]
  else:
    sListenOnThisIpAddress = None
  #
  objReceiverThread = threading.Thread(target = objClipboardSync.receiveDataLoop, args=(sListenOnThisIpAddress,))
  objReceiverThread.start()
  #
  # get the initial value 
  sLastClipboardContent = pyperclip.paste()
  #
  try:
    __logger.debug("start executing the main loop")
    while(__bExecuteMainLoop == True):
      if (objClipboardSync.isNewContentAvailable()):
        __logger.info("new content from other clients is available, updating local clipboard")
        sNewContent = objClipboardSync.getNewContent()
        pyperclip.copy(sNewContent)
        sLastClipboardContent = sNewContent
      else:
        #check if clipboard content has changed
        sCurrentClipboardContent = pyperclip.paste()
        if (sCurrentClipboardContent != sLastClipboardContent):
          __logger.info("clipboard content has changed locally, notifying known client(s) ...")
          objClipboardSync.updateClients(sCurrentClipboardContent)
          sLastClipboardContent = sCurrentClipboardContent
      time.sleep(0.7)
    #MainLoop exited gracefully, otherwise this part of the script is never reached
    objReceiverThread.do_run = False
    objReceiverThread.join()
    #
  except Exception as ex:
    __logger.error("exception caugth", exc_info = ex)
