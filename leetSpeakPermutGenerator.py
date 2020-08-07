# coding=utf-8

import argparse

'''
leetDict = {
  'a': ['/-\\','/\\','4','@'],
  'b': ['|3','8','|o'],
  'c': ['(','<','K','S'],
  'd': ['|)','o|','|>','<|'],
  'e': ['3'],
  'f': ['|=','ph'],
  'g': ['(','9','6'],
  'h': ['|-|',']-[','}-{','(-)',')-(','#'],
  'i': ['l','1','|','!',']['],
  'j': ['_|'],
  'k': ['|<','/<','\\<','|{'],
  'l': ['|_','|','1'],
  'm': ['|\\/|','/\\/\\',"|'|'|",'(\\/)','/\\','/|\\','/v\\'],
  'n': ['|\\|','/\\/','|\\\\|','/|/'],
  'o': ['0','()','[]','{}'],
  'p': ['|2','|D'],
  'q': ['(,)','kw'],
  'r': ['|2','|Z','|?'],
  's': ['5','$'],
  't': ['+',"][",'7'],
  'u': ['|_|'],
  'v': ['|/','\\|','\\/','/'],
  'w': ['\\/\\/','\\|\\|','|/|/','\\|/','\\^/','//'],
  'x': ['><','}{'],
  'y': ['`/',"'/",'j'],
  'z': ['2','(\\)']
}'''

leetDict = {
  'a': ['4','@'],
  'b': ['8'],
  'e': ['3'],
  'g': ['6'],
  'i': ['1','|','!'],
  'o': ['0'],
  's': ['5','$']
}

def permute(dictWord):
  if len(dictWord) > 0:
    currentLetter = dictWord[0]
    restOfWord = dictWord[1:]

    if currentLetter in leetDict:
        substitutions = leetDict[currentLetter] + [currentLetter]
    else:
        substitutions = [currentLetter]

    if len(restOfWord) > 0:
      perms = [s + p for s in substitutions for p in permute(restOfWord)]
    else:
      perms = substitutions
    return perms

parser = argparse.ArgumentParser(description='Permutate words of a wordlist.')
parser.add_argument('input_file', help='an input wordlist')
parser.add_argument('output_file', help='an output file for permuted wordlist')

args = parser.parse_args()

bplf = open(args.input_file, 'r')
profaneWords = bplf.read().splitlines()
bplf.close()

pplf = open(args.output_file, "w")

print 'Working...'

for profaneWord in profaneWords:
  try:
    pplf.writelines([p + '\n' for p in permute(profaneWord)])
  except Exception as e:
    pass

pplf.close()

print 'Done.'
