#!/bin/sh

set -xe

# Fetch the list of top-level domains from IANA.
curl -fSL -o 'tlds-alpha-by-domain.txt' \
  'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'

# Fetch the public suffix list.
curl -fSL -o 'public_suffix_list.dat' \
  'https://publicsuffix.org/list/public_suffix_list.dat'
