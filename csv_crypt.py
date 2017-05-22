"""Methods for encryption and decryption of CSV files and in-memory lists"""

import csv
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto import Random

def encrypt_csv_file(csv_path, encrypted_csv_path, password):
  """Encrypts an existing CSV file using the given password

  Args:
    csv_path: Path to unencrypted CSV file
    encrypted_csv_path: Path for encrypted output CSV file
    password: Password to decrypt the output file
  """
  csv_list = load_csv(csv_path)
  encrypt_csv(csv_list, encrypted_csv_path, password)

def decrypt_csv_file(encrypted_csv_path, decrypted_csv_path, password):
  """Decrypts an existing encrypted CSV file if given correct password

  Args:
    encrypted_csv_path: Path to existing encrypted CSV file
    decrypted_csv_path: Path for decrypted output CSV file
    password: Password to decrypt input file.
  """
  csv_list = load_encrypted_csv(encrypted_csv_path, password)
  write_csv(csv_list, decrypted_csv_path)

def load_csv(csv_path):
  """Loads unencrypted CSV file into memory

  Args:
    csv_path: Path to existing unencrypted CSV file
  Returns:
    csv_list: List containing each row of CSV as a sub-list containing each
      of the row's values.
      (Ex. "1,2,3\na,b,c" = [['1', '2', '3'], ['a', 'b', 'c']])
  """
  with open(csv_path, newline='') as csv_file:
    csv_reader = csv.reader(csv_file)
    csv_list = [row for row in csv_reader]
  return csv_list

def write_csv(csv_list, out_csv_path):
  """Writes CSV list representation to a file

  Args:
    csv_list: List representation of CSV
    out_csv_path: Path for output CSV file
  """
  with open(out_csv_path, 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    for row in csv_list:
      csv_writer.writerow(row)

def csv_to_bytes(csv_list):
  """Converts CSV list representation to bytes object"""
  csv_bytes = b''
  for row in csv_list:
    if row:
      for value in row:
        csv_bytes += str.encode("\"{}\",".format(value))
      csv_bytes = csv_bytes[:-1]
    csv_bytes += b"\r\n"
  return csv_bytes

def bytes_to_csv(csv_bytes):
  """Converts CSV bytes representation to list"""
  csv_list = []
  # Remove last item (Empty since CSV ends with newline)
  csv_reader = csv.reader(csv_bytes.decode().split('\r\n')[:-1])
  for row in csv_reader:
    csv_list.append(row)
  return csv_list

def derive_key_and_iv(password, salt, key_length, iv_length):
  """Auxilary function to generate key and iv for encryption/decryption

  Encryption/Decryption derived from:
  http://stackoverflow.com/questions/16761458/how-to-aes-encrypt-decrypt-files-using-python-pycrypto-in-an-openssl-compatible
  """
  key_and_iv = key_and_iv_chunk = b''
  while len(key_and_iv) < key_length + iv_length:
    key_and_iv_chunk = sha256(key_and_iv_chunk + password + salt).digest()
    key_and_iv += key_and_iv_chunk
  return key_and_iv[:key_length], key_and_iv[key_length:key_length+iv_length]

def encrypt_csv(in_csv, out_path, password, key_length=32):
  """Encrypts given CSV list and outputs to file

  Args:
    in_csv: CSV list representation
    out_path: Path for output encrypted CSV file
    password: Password to decrypt output file
    key_length: Length of key for encryption/decryption
  """
  with open(out_path, 'wb') as out_file:
    password = str.encode(password)
    block_size = AES.block_size
    salt = Random.new().read(block_size)# - len(b'Salted__'))
    key, i_v = derive_key_and_iv(password, salt, key_length, block_size)
    cipher = AES.new(key, AES.MODE_CBC, i_v)
    out_file.write(salt)#(b'Salted__' + salt)
    finished = False
    csv_bytes = csv_to_bytes(in_csv)
    while not finished:
      chunk = csv_bytes[:(1024 * block_size)]
      csv_bytes = csv_bytes[(1024 * block_size):]
      if len(chunk) == 0 or len(chunk) % block_size != 0:
        padding_length = (block_size - len(chunk) % block_size) or block_size
        chunk += padding_length * str.encode(chr(padding_length))
        finished = True
      out_file.write(cipher.encrypt(chunk))

def decrypt_csv(in_path, password, key_length=32):
  """Decrypts given encrypted CSV file and converts to list object

  Args:
    in_path: Path to encrypted CSV file
    password: Password to decrypt input file
    key_length: Length of key for encryption/decryption
  Returns:
    csv_list: List containing each row of CSV as a sub-list containing each
      of the row's values.
      (Ex. "1,2,3\na,b,c" = [['1', '2', '3'], ['a', 'b', 'c']])
  """
  with open(in_path, 'rb') as in_file:
    password = str.encode(password)
    block_size = AES.block_size
    salt = in_file.read(block_size)#[len(b'Salted__'):]
    key, i_v = derive_key_and_iv(password, salt, key_length, block_size)
    cipher = AES.new(key, AES.MODE_CBC, i_v)
    next_chunk = b''
    finished = False
    csv_bytes = b''
    while not finished:
      chunk = next_chunk
      next_chunk = cipher.decrypt(in_file.read(1024 * block_size))
      if len(next_chunk) == 0:
        padding_length = chunk[-1]
        if padding_length < 1 or padding_length > block_size:
          raise ValueError("Password incorrect")
        chunk = chunk[:-padding_length]
        finished = True
      csv_bytes += chunk
    try:
      csv_list = bytes_to_csv(csv_bytes)
    except:
      raise ValueError("Password incorrect")
    return csv_list
