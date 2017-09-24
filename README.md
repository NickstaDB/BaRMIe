# BaRMIe
BaRMIe is a tool for enumerating and attacking Java RMI (Remote Method Invocation) services.

RMI services often expose dangerous functionality without adequate security controls, however RMI services tend to pass under the radar during security assessments due to the lack of effective testing tools. In 2008 Adam Boulton spoke at AppSec USA ([YouTube](https://www.youtube.com/watch?v=owN9EnoLsFY)) and released some RMI attack tools which disappeared soon after, however even with those tools a successful zero-knowledge attack relies on a significant brute force attack (~64-bits/9 quintillion possibilities) being performed over the network.

The goal of BaRMIe is to enable security professionals to identify, attack, and secure insecure RMI services. Using partial RMI interfaces from existing software, BaRMIe can interact directly with those services without first brute forcing 64-bits over the network.

### Disclaimer
BaRMIe was written to aid security professionals in identifying insecure RMI services on systems which the user has prior permission to attack. Unauthorised access to computer systems is illegal and BaRMIe must be used in accordance with all relevant laws. Failure to do so could lead to you being prosecuted. The developers of BaRMIe assume no liability and are not responsible for any misuse or damage caused by this program.

## Usage
Use of BaRMIe is straightforward. Run BaRMIe with no parameters for usage information.

    $ java -jar BaRMIe.jar
      ▄▄▄▄    ▄▄▄       ██▀███   ███▄ ▄███▓ ██▓▓█████
     ▓█████▄ ▒████▄    ▓██ ▒ ██▒▓██▒▀█▀ ██▒▓██▒▓█   ▀
     ▒██▒ ▄██▒██  ▀█▄  ▓██ ░▄█ ▒▓██    ▓██░▒██▒▒███
     ▒██░█▀  ░██▄▄▄▄██ ▒██▀▀█▄  ▒██    ▒██ ░██░▒▓█  ▄
     ░▓█  ▀█▓ ▓█   ▓██▒░██▓ ▒██▒▒██▒   ░██▒░██░░▒████▒
     ░▒▓███▀▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░   ░  ░░▓  ░░ ▒░ ░
     ▒░▒   ░   ▒   ▒▒ ░  ░▒ ░ ▒░░  ░      ░ ▒ ░ ░ ░  ░
      ░    ░   ░   ▒     ░░   ░ ░      ░    ▒ ░   ░
      ░            ░  ░   ░            ░    ░     ░  ░
           ░                                     v1.0
                 Java RMI enumeration tool.
                   Written by Nicky Bloor (@NickstaDB)

    Warning: BaRMIe was written to aid security professionals in identifying the
             insecure use of RMI services on systems which the user has prior
             permission to attack. BaRMIe must be used in accordance with all
             relevant laws. Failure to do so could lead to your prosecution.
             The developers assume no liability and are not responsible for any
             misuse or damage caused by this program.

    Usage:
      BaRMIe -enum [options] [host] [port]
        Enumerate RMI services on the given endpoint(s).
        Note: if -enum is not specified, this is the default mode.
      BaRMIe -attack [options] [host] [port]
        Enumerate and attack the given target(s).
    Options:
      --threads  The number of threads to use for enumeration (default 10).
      --timeout  The timeout for blocking socket operations (default 5,000ms).
      --targets  A file containing targets to scan.
                 The file should contain a single host or space-separated
                 host and port pair per line.
                 Alternatively, all nmap output formats are supported, BaRMIe will
                 parse nmap output for port 1099, 'rmiregistry', or 'Java RMI'
                 services to target.
                 Note: [host] [port] not supported when --targets is used.
    Reliability:
        A +/- system is used to indicate attack reliability as follows:
          [+  ]: Indicates an application-specific attack
          [-  ]: Indicates a JRE attack
          [ + ]: Attack insecure methods (such as 'writeFile' without auth)
          [ - ]: Attack Java deserialization (i.e. Object parameters)
          [  +]: Does not require non-default dependencies
          [  -]: Non-default dependencies are required

Enumeration mode (-enum) extracts details of objects that are exposed through an RMI registry service and lists any known attacks that affect the endpoint.

Attack mode (-attack) first enumerates the given targets, then provides a menu system for launching known attacks against RMI services.

A single target can be specified on the command line. Alternatively BaRMIe can extract targets from a simple text file or nmap output.

## No Vulnerable Targets Identified?
Great! This is your opportunity to help improve BaRMIe! BaRMIe relies on *some* knowledge of the classes exposed over RMI so contributions will go a long way in improving BaRMIe and the security of RMI services.

If you have access to JAR files or source code for the target application then producing an attack is as simple as compiling code against the relevant JAR files. Retrieve the relevant remote object using the *LocateRegistry* and *Registry* classes and call the desired methods. Alternatively look for remote methods that accept arbitrary objects or otherwise non-primitive parameters as these can be used to deliver deserialization payloads. More documentation on attacking RMI and producing attacks for BaRMIe will be made available in the near future.

Alternatively, [get in touch](https://nickbloor.co.uk/contact/), and provide as much detail as possible including BaRMIe -enum output and ideally the relevant JAR files.

## Attack Types
BaRMIe is capable of performing three types of attacks against RMI services. A brief description of each follows. Further technical details will be published in the near future at [https://nickbloor.co.uk/](https://nickbloor.co.uk/). In addition to this, I presented the results of my research at 44CON 2017 and the slides can be found here: [BaRMIe - Poking Java's Back Door](https://www.slideshare.net/NickBloor3/nicky-bloor-barmie-poking-javas-back-door-44con-2017).

### 1. Attacking Insecure Methods
The first and most straightforward method of attacking insecure RMI services is to simply call insecure remote methods. Often dangerous functionality is exposed over RMI which can be triggered by simply retrieving the remote object reference and calling the dangerous method. The following code is an example of this:

    //Get a reference to the remote RMI registry service
    Registry reg = LocateRegistry.getRegistry(targetHost, targetPort);
    
    //Get a reference to the target RMI object
    Foo bar = (Foo)reg.lookup(objectName);
    
    //Call the remote executeCommand() method
    bar.executeCommand(cmd);

### 2. Deserialization via Object-type Paraeters
Some RMI services do not expose dangerous functionality, or they implement security controls such as authentication and session management. If the RMI service exposes a method that accepts an arbitrary Object as a parameter then the method can be used as an entry point for deserialization attacks. Some examples of such methods can be seen below:

    public void setOption(String name, Object value);
    public void addAll(List values);

### 3. Deserialization via Illegal Method Invocation
Due to the use of serialization, and insecure handling of method parameters on the server, it is possible to use any method with non-primitive parameter types as an entry point for deserialization attacks. BaRMIe achieves this by using TCP proxies to modify method parameters at the network level, essentially triggering illegal method invocations. Some examples of vulnerable methods can be seen below:

    public void setName(String name);
    public Long add(Integer i1, Integer i2);
    public void sum(int[] values); 

The parameters to each of these methods can be replaced with a deserialization payload as the method invocation passes through a proxy. This attack is possible because Java does not attempt to verify that remote method parameters received over the network are compatible with the actual parameter types before deserializing them.
