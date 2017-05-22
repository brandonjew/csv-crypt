# csv-crypt

Methods for encryption and decryption of CSV files. Allows encrypted CSV files to be decrypted and loaded into memory in a list structure. Uses SHA-256 hashing.

## main methods

### load_encrypted_csv(encrypted_csv_path, password)
* Decrypts CSV and loads into memory (list)

### encrypt_csv_file(csv_path, encrypted_csv_path, password)
* Encrypts CSV file and writes to new file

### decrypt_csv_file(encrypted_csv_path, decrypted_csv_path, password)
* Decrypts CSV file and writes to new file

## todo
* Write object that behaves like csv.reader for encrypted CSV files
