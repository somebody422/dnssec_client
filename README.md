# Note: This repo is a public copy of a project done for Data Communication and Networks (CSCI-351) in fall 2018

# data_comm_project4

* Sam Hedin
* Chris Grace

## APPROACH:
This project mostly re-uses project 2, but adds dnssec abilities. This involved checking the RRSIGs after each query is 
made, and establishing a chain-of-trust to verify the server's public key.

There isn't too much about our design that we think are good. Creating a class hierarchy for the records is one
good design choice we've made. The functionality is somewhat well broken up. One thing is for sure, if there is anything wrong
with the DNSSEC portion of a domain name, our program shouldn't allow it.

We tested by running our code against a few dns-sec enabled servers. We attempted to test against the provided
test servers, but they were intermittently unavailable, such as right at this moment. We've tested for the
most part with example.com, so if all else fails that should work fine.

Some challenges we faced along the way were dealing with domain names. Especially the names that were pointers.
Even worse were names that were part pointer and part new domain. We have limited support for this and are
worried that this may result in a loss credit, but here's hoping!

An additional challenge was verification of signatures. Having trouble with the whole 'canonical name' thing,
we sort of just try all orders of the RRset. Hey, it works.

## USAGE:

On glados, all packages were available. A pip freeze is including in requirements.txt just in case.
RUN runme.sh FIRST!

'./351dnsclient @RESOLVER DOMAIN-NAME RECORD-TYPE'

For example:
'./351dnsclient @8.8.8.8 example.com A'
This command will fetch A records from example.com while doing correct dns-sec validation.
