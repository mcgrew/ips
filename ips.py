#!/usr/bin/env python3

import struct
import argparse

def create_ips(file1_content, file2_content):
  return Patch.create(file1_content, file2_content).encode()

def apply_ips(file_content, patch_content):
  patch = Patch(patch_content)
  return patch.apply(file_content)

class Patch:
  records = [] 
  def __init__(self, ips_content=None):
    if ips_content and ips_content[:5] == b'PATCH':
      # trim 'PATCH' from the beginning and 'EOL' from the end.
      ips_ptr = 0
      ips_content = ips_content[5:-3]
      # parse the patches
      while (ips_ptr < len(ips_content)):
        record_meta = struct.unpack_from(">BHH", ips_content, ips_ptr)
        ips_ptr += 5
        record_addr = record_meta[0] << 16 | record_meta[1]
        record_size = record_meta[2]
        if record_size:
          record_content = struct.unpack_from("B" * record_size, ips_content, 
              ips_ptr)
          ips_ptr += record_size
        else: #run length encoded
          record_size = struct.unpack_from("B", ips_content, ips_ptr)
          ips_ptr += 2
          record_content = struct.unpack_from("B", ips_content, ips_ptr) \
              * record_size
          ips_ptr += 1
        self.records.append(Record(record_addr, record_content))
    
  def apply(self, orig_content):
    orig_content = bytearray(orig_content)
    for record in self.records:
      orig_content[record.address:record.address+record.size()] = record.content
    return orig_content

  def encode(self):
    encoded =  b''.join([r.encode() for r in self.records])
    return b''.join((b'PATCH', encoded, b'EOL'))

  def add_record(self, address, content):
    self.records.append(Record(address, content))

  @staticmethod
  def create(orig_content, patched_content):
    p = Patch()
    if not len(orig_content) == len(patched_content):
      raise ValueError("File sizes do not match.")
    diff_addr = -1
    last_diff = -1
    for i in range(len(orig_content)):
      if not orig_content[i] == patched_content[i]:
        if diff_addr < 0:
          diff_addr = i
        last_diff = i
      if last_diff >= 0 and i - last_diff >= 5:
        p.add_record(diff_addr, patched_content[diff_addr:last_diff+1])
        diff_addr = -1
        last_diff = -1
    return p

class Record:
  def __init__(self, address, content=None):
    self.address = address 
    self.content = content

  def set_addr(self, addr):
    self.address = addr

  def set_content(self, content):
    self.content = content

  def size(self):
    if self.content:
      return len(self.content)
    else:
      return 0

  def encode(self):
    return struct.pack('>BHH' + 'B' * self.size(), self.address >> 16, 
        self.address & 0xff, self.size(), *[int(b) for b in self.content])
    

def main():
  parser = argparse.ArgumentParser(prog="ips",
      description="A utility for creating and appying IPS patches")
  parser.add_argument("-o","--output", type=str,
      help="The file name to be written.")
  parser.add_argument("file1", help="The first input file")
  parser.add_argument("file2", help="The second input file")
  args = parser.parse_args()

  patch_content = None

  file1 = open(args.file1, 'rb')
  file1_content = file1.read()
  file1.close()
  file2 = open(args.file2, 'rb')
  file2_content = file2.read()
  file2.close()

  if file1_content[:5] == b'PATCH':
    patch_content = file1_content
    file1_content = file2_content
    file2_content = None
  elif file2_content[:5] == b'PATCH':
    patch_content = file2_content
    file2_content = None
  
  if patch_content:
    out = apply_ips(file1_content, patch_content)
  else:
    out = create_ips(file1_content, file2_content)
  
  outfile = open(args.output, 'wb')
  outfile.write(out)
  outfile.close()


if __name__ == "__main__":
  main()


