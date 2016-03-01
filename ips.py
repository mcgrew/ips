#!/usr/bin/env python3

import struct
import argparse

def create_ips(file1_data, file2_data):
  pass

def apply_ips(file_data, patch_data):
  file_ptr = 0
  patch_ptr = 5
  file_size = len(file_data)
  file_data = bytearray(file_data)
  # read and apply the patches
  while (patch_ptr < len(patch_data)):
    record_meta = struct.unpack(">BHH", patch_data, patch_ptr)
    patch_ptr += 5
    record_addr = record_meta[0] << 16 | record_meta[1]
    record_size = record_meta[2]
    record_data = struct.unpack(">" + "B" * record_size, patch_data, patch_ptr)
    patch_ptr += record_size
    file_data[record_addr:record_addr+record_size] = record_data
  # file size should not have changed
  if not file_size == len(file_data):
    pass #throw some kind of error or warning here
  return file_data


def main():
  parser = argparse.ArgumentParser(prog="ips",
      description="A utility for creating and appying IPS patches")
  parser.add_argument("-o","--output", type=str,
      help="The file name to be written.")
  parser.add_argument("file1", help="The first input file")
  parser.add_argument("file2", help="The second input file")
  args = parser.parse_args()

  patch_data = None

  file1 = open(args.file1, 'r')
  file1_data = file1.read()
  file1.close()
  file2 = open(args.file2, 'r')
  file2_data = file2.read()
  file2.close()

  if file1_data[:5] == 'PATCH':
    patch_data = file1_data
    file1_data = file2_data
    file2_data = None
  elif file2_data[:5] == 'PATCH':
    patch_data = file2_data
    file2_data = None
  
  if patch_data:
    out = apply_ips(file1_data, patch_data)
  else:
    out = create_ips(file1_data, file2_data)
  
  outfile = open(args.output, 'w')
  outfile.write(out)
  outfile.close()


if __name__ == "__main__":
  main()


