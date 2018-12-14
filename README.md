# data_comm_project4

* Sam Hedin
* Chris Grace

## APPROACH:
This project mostly re-uses project 2, but adds dnssec abilities. This involved checking the RRSIGs after each query is made, and establishing a chain-of-trust to verify the server's public key

We tested by running our code against a few dns-sec enabled servers.

## USAGE:


'python ./351dnsclient.py @RESOLVER DOMAIN-NAME RECORD-TYPE'

For example:
'python ./351dnsclient.py @8.8.8.8 example.com A'
This command will fetch A records from example.com while doing correct dns-sec validation.
