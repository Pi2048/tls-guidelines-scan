tls-guidelines-scan
===================

A wrapper around sslyze that interprets the results in the context of the IT security guidelines for Transport Layer Security of NCSC-NL

__This script is in alpha and should not be used for production use without extensive testing__

**Introduction**

NCSC-NL has published guidelines on securely configuring Transport Layer Security (TLS). Sslyze scans servers that offer TLS to determine their configuration. This script is a wrapper around sslyze. It interprets the results against the guidelines of NCSC-NL.

NCSC-NL has in no way endorsed this wrapper script. This is a private initiative based upon their guidelines.

Guidelines of NCSC-NL (in Dutch):

    https://www.ncsc.nl/dienstverlening/expertise-advies/kennisdeling/whitepapers/ict-beveiligingsrichtlijnen-voor-transport-layer-security-tls.html

You can get sslyze from:

    https://github.com/nabla-c0d3/sslyze/releases

The sslyze project page is at:

    https://github.com/nabla-c0d3/sslyze

**Installation**

You don't install the script. Rather, you place it in the same directory as sslyze.py and call it from there.

1. Download a release version of sslyze from https://github.com/nabla-c0d3/sslyze/releases.

2. Unpack the sslyze download and attempt to run sslyze.py on a website. If this doesn't succeed, fix any problems you have. I don't know how to do that: I'm not the maintainer of sslyze.

3. Grab the analyse.py script from this repository and place it in the same directory as sslyze.py.

4. Call analyse.py directly as instructed below.

**Usage**

The script analyse.py calls the sslyze.py script with the appropriate options. You place analyse.py in the same directory as sslyze.py and call

    $ python analyse.py <host> <port>

To check the configuration of the HTTPS website at example.com on the default HTTPS port, do:

    $ python analyse.py example.com 443

The script calls several sslyze options automatically. Should you require more, just append them after the call:

    $ python analyse.py example.com 25 --starttls=smtp

The script will automatically pass them to sslyze.py.

**Suitability for use**

This script was put together on a Sunday afternoon. It should *not* be used for production purposes. 

In particular, some functionality has not been tested at all. The verification for guideline B4-2 always returns True because you can't check adherence to this guideline remotely.

If you find it useful, please contribute by using it on many servers and complaining if something breaks (via Issues).


