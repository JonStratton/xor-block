#!/usr/bin/env python3
__author__ = 'Jon Stratton'
import fileinput, getopt, sys, re

def xOrBlock(inList, keyList):
   outList = []
   index = 0
   for item in inList:
      keyInt = keyList[index % len(keyList)]
      outList.append(item ^ keyInt)
      index = index + 1
   return(outList)

def inputFile(inFile):
   inText = ''
   if inFile == '-':
      for line in sys.stdin:
         inText = inText + line
   elif inFile and os.path.exists(inFile):
      f = open(inFile, 'r')
      lines = f.readlines()
      for line in lines:
         #line = line.replace("\n","")
         inText = inText + line
   return inText

def parseCsharp(inText):
   # First, pull out the shellcode
   inText = inText.replace("\n","")
   arrayCsharpRegex = re.compile(r'{(.*)}')
   inShellcode = arrayCsharpRegex.search(inText).group(1)

   # Then convert the shellcode to an array of ints
   inList = []
   for item in inShellcode.split(','):
      inList.append(int(item, 16))
   return inList

def outputCsharp(outList):
   lines = []
   i = 0
   for item in outList:
      linesI = int(i / 12)
      if linesI < len(lines):
         lines[linesI] = lines[linesI] + ',' + str(hex(item))
      else:
         lines.append(str(hex(item)))
      i = i + 1
   outText = 'byte[] buf = new byte[' + str(len(outList)) + '] {' + ",\n".join(lines) + '};'
   return outText

def parseVb(inText):
   # First, pull out the shellcode
   inText = inText.replace("\n",'')
   inText = inText.replace('_','')
   arrayCsharpRegex = re.compile(r'Array\((.*)\)')
   inShellcode = arrayCsharpRegex.search(inText).group(1)

   # Then convert the shellcode to an array of ints
   inList = []
   for item in inShellcode.split(','):
      inList.append(int(item))
   return inList

def outputVb(outList):
   lines = []
   i = 0
   for item in outList:
      linesI = int(i / 40)
      if linesI < len(lines):
         lines[linesI] = lines[linesI] + ',' + str(item)
      else:
         lines.append(str(item))
      i = i + 1
   outText = 'buf = Array(' + " _\n".join(lines) + ')'
   return outText

def parseC(inText):
   # First, pull out the shellcode
   inText = inText.replace("\n","")
   inText = inText.replace('"','')
   arrayCsharpRegex = re.compile(r'= (.*);')
   inShellcode = arrayCsharpRegex.search(inText).group(1)

   # Then convert the shellcode to an array of ints
   inList = []
   for item in inShellcode.split("\\"):
      if item:
         item = '0' + item
         inList.append(int(item, 16))
   return inList

def outputC(outList):
   lines = []
   i = 0
   for item in outList:
      linesI = int(i / 14)
      if linesI < len(lines):
         lines[linesI] = lines[linesI] + str(hex(item)).replace('0x', '\\x')
      else:
         lines.append(str(hex(item)).replace('0x', '\\x'))
      i = i + 1
   outText = "unsigned char buf[] = \n\"" + "\"\n\"".join(lines) + '";'
   return outText

def parsePs(inText):
   # First, pull out the shellcode
   inText = inText.replace("\n","")
   arrayCsharpRegex = re.compile(r'= (.*)')
   inShellcode = arrayCsharpRegex.search(inText).group(1)

   # Then convert the shellcode to an array of ints
   inList = []
   for item in inShellcode.split(','):
      inList.append(int(item, 16))
   return inList

def outputPs(outList):
   i = 0
   for item in outList:
      outList[i] = str(hex(item))
      i = i + 1
   outText = '[Byte[]] $buf = ' + ','.join(outList)
   return outText

if (__name__ == '__main__'):
   keyList = []
   inFormat = 'csharp'
   inFile = ''

   myopts, args = getopt.getopt(sys.argv[1:],'k:f:i:')
   for o, a in myopts:
      if o == '-k':
         in_string  = a
         for i in a.split(','):
            keyList.append(int(i))
      elif o == '-f':
         inFormat  = a
      elif o == '-i':
         inFile  = a

   outText = ''
   inText = inputFile(inFile)
   if inFormat == 'csharp':
      inList = parseCsharp(inText)
      outList = xOrBlock(inList, keyList)
      outText = outputCsharp(outList)
   elif inFormat == 'vbapplication':
      inList = parseVb(inText)
      outList = xOrBlock(inList, keyList)
      outText = outputVb(outList)
   elif inFormat == 'c':
      inList = parseC(inText)
      outList = xOrBlock(inList, keyList)
      outText = outputC(outList)
   elif inFormat == 'ps1':
      inList = parsePs(inText)
      outList = xOrBlock(inList, keyList)
      outText = outputPs(outList)
   else:
      print('Error, unhandled format: ' + inFormat)
   print(outText)
