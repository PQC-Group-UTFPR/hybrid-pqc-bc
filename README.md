# hybrid-pqc-bc

A repository for an example of implementing hybrid PQC using Bouncy Castle.

# Disclaimer

This repository is experimental and should not be used for production environments. Use it at your own risk.

# Dependencies

Check pom.xml for dependencies. 

# Key-Establishment Method: Execution

Default points to hybrid mode; passing args will switch to PQ-only mode. Currently Kyber-768 (with or without ECDH P-384) is supported.

It's mvn-based repository; so one can build with `mvn` commands and then execute with `java -jar <build-filename>.jar` or import the repository in your IDE.

Example: `mvn exec:java -Dexec.mainClass="grupopqc.utfprtd.hybridexample.KEMSpeedTest"  -Dexec.args="-m KYBER -c xECDH -n 500"`


# Contributions

Check issues or TODO's in the code. 
