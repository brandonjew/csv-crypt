# csv-crypt

Methods for encryption and decryption of CSV files. Allows encrypted CSV files to be decrypted and loaded into memory in a list structure. Uses SHA-256 hashing.

## main methods

#### encrypt_csv_file(csv_path, encrypted_csv_path, password)
* Encrypts CSV file and writes to new file

#### decrypt_csv_file(encrypted_csv_path, decrypted_csv_path, password)
* Decrypts CSV file and writes to new file

#### encrypt_csv(in_csv, out_path, password, key_length=32)
* Encrypts CSV list object and writes to file

#### decrypt_csv(in_path, password, key_length=32)
* Decrypts CSV file and loads into memory. Returns CSV list object. 

## todo
* Write object that behaves like csv.reader for encrypted CSV files
* Write method for accessing encrypted files one chunk at a time.
