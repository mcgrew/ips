#!/usr/bin/env python3

import struct
import argparse

def create_ips(file1_data, file2_data):
  pass

def apply_ips(file_data, patch_data):
  patch = Patch(patch_data)
  return patch.apply(file_data)

class Patch:
  records = [] 
  def __init__(self, ips_data=None):
    if data and data[:5] == 'PATCH':
      ips_ptr = 5
      file_size = len(file_data)
      # read and apply the patches
      while (ips_ptr < len(ips_data)):
        record_meta = struct.unpack(">BHH", ips_data, ips_ptr)
        ips_ptr += 5
        record_addr = record_meta[0] << 16 | record_meta[1]
        record_size = record_meta[2]
        if record_size:
          record_data = struct.unpack("B" * record_size, ips_data, ips_ptr)
          ips_ptr += record_size
        else: #run length encoded
          record_size = struct.unpack("B", ips_data, ips_ptr)
          ips_ptr += 2
          record_data = struct.unpack("B", ips_data, ips_ptr) * record_size
          ips_ptr += 1
        records.push(Record(record_addr, record_data))
    
    def apply(self, orig_data):
      orig_data = bytearray(file_data)
      for record in records:
        orig_data[record.address:record.address+record.size()] = record.data
      return orig_data

    @staticmethod
    def create(orig_data, patched_data):
      pass

class Record:
  def __init__(self, address, data=None):
    self.address = address 
    self.data = data

  def set_addr(self, addr):
    self.address = addr

  def set_data(self, data):
    self.data = data

  def size(self):
    if self.data:
      return len(self.data)
    else:
      return 0

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


