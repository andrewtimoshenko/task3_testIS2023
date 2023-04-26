# task3_testIS2023

You need to write a program in C language, which will process messages:
- read pairs of message and mask from file (see Message input format)
- check CRC-32 for data field (see Important notes)
- add zero padding to the data bytes if it is not a multiple of 4
- divide data bytes in tetrads and apply mask to even tetrads
- calculate CRC-32 for new data bytes
- save results to output file (see Output information format)

Message input format:
```
|-------------------------------------------|
|  0   |   1    | 2...253 | 254...257       |
|-------------------------------------------|
| Type | Length |           Payload         |
|-------------------------------------------| 
|               |   data  |    CRC-32       |
|-------------------------------------------| 
```
- message leaded by keyword `mess=`

Mask input format:
- 32 bits value 
- mask leaded by keyword `mask=`

Output information format (for each message):
- message type
- initial message length
- initial message data bytes
- initial CRC-32
- modified message length
- modified message data bytes with mask
- modified CRC-32
  
Important notes:
- input file name - data_in.txt
- output file name - data_out.txt
- input and output files stored in the same directory as the program itself
- if output file exist, it have to be updated with new information
- all errors have to be saved in output file
- all data in input file stored in ASCII hex format
- all data stored in ASCII hex format
- CRC-32 polynome 0x04C11DB7, initial value 0xFFFFFFFF