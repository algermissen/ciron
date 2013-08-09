ciron
=====

A C implementation of [iron](https://github.com/hueniverse/iron).

Building ciron
==============

ciron depends in libcrypto of the OpenSSL distribution, so you need that to be
available on your system (configure will try to locate libcrypto for you).

Run the configure script for environment checks and Makefile generation then make:

    $ ./configure
    $ make all
    
This builds a static library in the ciron directory named libciron.a which you
need to link to your own projects to include ciron. Dynamic linking is not
provided at this point.

The build creates a command line utility _iron_ in the iron directory.
This can be used to seal or unseal arbitrary input. Have a look at the sources
in iron/iron.c to see how to use the ciron library.

After the build, you should run the tests using

    $ make test


ciron has been build and tested in the following environments:

* Linux (CentOS)
* MacOS 10.7


If you have built ciron on a different environment, please drop me a not so I can
include that environment in the list above.


A note on building on MacOS
---------------------------
During building on MacOS 10.7 and above, you will see deprecation warnings for
all the OpenSSL (libcrypto) functions. These deprecations exist due to Apple's
recent rework of the security architecture. Background information can be
found, for example, in [this Stackoverflow answer](http://stackoverflow.com/a/7406994/267196).

Encoding Issues
===============

The library interprets all incoming data as byte sequences to stay clear of any encoding
issues. If you are sealing strings, you have to provide them in UTF-8 encoded unsigned
char arrays.


Security Considerations
=======================

Make sure you read the [security considerations](https://github.com/hueniverse/iron#security-considerations) of iron before using this 
library.

Please note that this is not yet a production-ready software, primarily because it has not yet been applied in
a production-like testing environment.

Specifically, there are the following open issues regarding security:

* libcrypto (the OpenSSL library used) is not a trivial piece of software and it is also not documented very clearly. I would like to have at least one OpenSSL expert review my code.
* I am currently unclear whether I have to apply memory locking inside libciron to prevent the master password from being paged to disk. But
please note that no copy of the incoming master password is made inside the library. (Not sure about libcrypto though)


Underlying Crypto-Library
=========================

ciron currently builds upon the cryptographic functions provided by libcrypto
of the OpenSSL distribution.

If you need to use a different underlying crypto library, you must create an
implementation of the functions declared in `ciron/crypto.h`. Have a look at
`ciron/crypto_openssl.c` to see how that works. The other parts of ciron do not
depend on OpenSSL.

Implementation Concepts
=======================

Some useful notes about the implementation approach:

* None of the functions \0 terminate what they create.
* No internal memory allocation is done inside libciron. (Not sure about the portions of libcrypto that I am using).

Until developer documentation for ciron is ready, please consult the `ciron/ciron.h` header file and the source code
of the command line utility `iron/iron.c`. These should give you a good explanation as there are really only two 
core functions: `seal()` and `unseal()`.


The iron Command Line Utility
============================

The iron utility can be used to seal and unseal data on the command line.

    $ echo "Data to be kept secret" | iron -p some_password > token
    
    $ cat token | iron -p some_password -u


This is useful for cross-language test cases and debugging or for manually generating
encapsulated tokens.

While ciron is intended to be used for relatively small amounts of data, such
as authentcation and authorization tokens, the library can be used for
processing larger amounts of data. You can try this using the test data supplied
in `test/data`. For example

    $ cat test/data/grandinquisitor.txt | iron -p some_pwd > token

    $ cat token | iron -p some_pwd -u

Note to Implementors
====================

When you plan to add features to ciron, please carefully note the following:

* calculate_encryption_buffer_length() currently hard codes a 16byte cipher block size (which is correct for all CBC algorithms). This should be made dynamic if non-CBC algorithms are used.
  See https://github.com/algermissen/ciron/issues/5
  
* If you add algorithms, you must check and maybe adjust several buffer size macros in ciron.h and common.h
  These mocros are set the the maximum necessary length of cryptographic elements such as keys possibly used by ciron. Hence, they
  depend on the actual algorithms provided.





