# hybrid-pqc-bc

A repository for an example of implementing hybrid PQC using Bouncy Castle.

# Disclaimer

This repository is experimental and should not be used for production environments. Use it at your own risk.

# Dependencies

Check pom.xml for dependencies. 

# Key-Establishment Method: Execution

There's two classes: KEMSpeedTest.java (default main class) and HybridKEMExample.java (for a single example).

HybridKEMExample.java has one argument which points to hybrid mode as default; passing args will switch to PQ-only mode. 

KEMSpeedTest.java has more flags (see below). 

It's a mvn-based repository; so one can build with `mvn` commands and then execute with `java -jar <build-filename>.jar` or import the repository in your IDE.

Example: `mvn exec:java -Dexec.mainClass="grupopqc.utfprtd.hybridexample.KEMSpeedTest"  -Dexec.args="-m KYBER -c xECDH -n 500"`

Flags:

- `-m` used to select the PQC algorithm (only "KYBER" is supported for now).
- `-c` you can alternate the hybrid component. "NIST P-Curves" or "xECDH".
- `-n` you can set the number of operations. For example, `-n 10` will generate 10 keys, perform 10 encaps and 10 decaps (if you run KEMSpeedTest.java).


# Composite Certs and Keys:

TODO.

# Contributions

Check issues or TODO's in the code. 
