
# Developers

* Sam Hedin
* Chris Grace

## APPROACH:

We tested by running our code against a few dns-sec enabled servers. We attempted to test against the provided
test servers, but they were intermittently unavailable, such as right at this moment. We've tested for the
most part with example.com, so if all else fails that should work fine.

An challenge was verification of signatures. Having trouble with the whole 'canonical name' thing,
we sort of just try all orders of the RRset. Hey, it works.

## USAGE:

'./351dnsclient @RESOLVER DOMAIN-NAME RECORD-TYPE'

For example:
'./351dnsclient @8.8.8.8 example.com A'
This command will fetch A records from example.com while doing correct dns-sec validation.
