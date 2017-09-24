package nb.barmie.modes.attack;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InvalidClassException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.UnmarshalException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.SecureRandom;
import java.util.ArrayList;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.exceptions.BaRMIeGetObjectException;
import nb.barmie.exceptions.BaRMIeInputException;
import nb.barmie.exceptions.BaRMIeWriteFileException;
import nb.barmie.modes.enumeration.RMIEndpoint;
import nb.barmie.modes.enumeration.RMIObject;
import nb.barmie.net.proxy.PortForwarder;
import nb.barmie.net.proxy.ProxyServer;
import nb.barmie.net.proxy.RMIObjectUIDFixingProxy;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * RMIAttack base class.
 * 
 * All RMI attacks must extend this class and implement the following methods:
 *	canAttackEndpoint(RMIEndpoint): Return true if the attack can be used against the given RMI endpoint.
 *	executeAttack(RMIEndpoint): Execute the attack.
 * 
 * Ideally RMI attacks should also call the various setters to configure
 * properties including a brief (one-liner, what does it achieve) and detailed
 * description of the attack (more detailed e.g. to report to system owner).
 * 
 * Helper methods are provided to perform common tasks whilst executing an RMI
 * attack, such as reading input from STDIN (e.g. to get attack parameters),
 * or requesting an object from an RMI registry.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public abstract class RMIAttack implements Comparable<RMIAttack> {
	/*******************
	 * Constants
	 ******************/
	protected final String REMEDIATION_NO_FIX = "No fix currently available. Consider implementing network-layer access controls for this service.";
	
	/*******************
	 * Properties
	 ******************/
	private boolean _isAppSpecific;				//True if the attack applies to specific RMI applications (as opposed to being generic as in the Registry.bind() attack)
	private boolean _isDeserAttack;				//True if the attack targets deserialization
	private boolean _nonDefaultDependency;		//True if a non-default dependency is required (e.g. deser)
	private String _description;				//A brief description of the attack.
	private String _detail;						//Detailed description
	private String _remediation;				//Remediation advice
	protected ProgramOptions _options;			//Program options object (i.e. for socket timeout value)
	protected ArrayList<ProxyServer> _proxies;	//Proxy servers used by the attack, these are shut down by the cleanUp method after an attack has been executed
	
	/*******************
	 * Default constructor, sets all properties to reasonable defaults.
	 ******************/
	public RMIAttack() {
		this._isAppSpecific = true;
		this._isDeserAttack = false;
		this._nonDefaultDependency = false;
		this._description = "";
		this._detail = "";
		this._remediation = "";
		this._options = null;
		this._proxies = new ArrayList<ProxyServer>();
	}
	
	/*******************
	 * Check whether this attack can be used against the given RMI endpoint.
	 * 
	 * @param ep The enumerated RMI endpoint.
	 * @return True if the attack can be used against the given endpoint.
	 ******************/
	public abstract boolean canAttackEndpoint(RMIEndpoint ep);
	
	/*******************
	 * Execute the attack against the given RMI endpoint.
	 * 
	 * It is the responsibility of the subclass to prompt the user for any
	 * attack-specific parameters.
	 * 
	 * @param ep The enumerated RMI endpoint.
	 ******************/
	public abstract void executeAttack(RMIEndpoint ep) throws BaRMIeException;
	
	/*******************
	 * Custom clean up method which can be overridden by sub classes in order
	 * to perform custom post-attack clean up.
	 ******************/
	protected void doCustomCleanUp() { }
	
	/*******************
	 * Perform post-attack cleanup, for example shut down port forwarders etc.
	 * 
	 * Sub classes can override doCustomCleanUp() to implement custom clean up.
	 ******************/
	public final void cleanUp() {
		//Perform custom cleanup
		this.doCustomCleanUp();
		
		//Shutdown all proxies
		for(ProxyServer p: this._proxies) {
			p.stopProxy(true);
		}
		this._proxies.clear();
	}
	
	/*******************
	 * Compare method for sorting attacks - those with non-default dependencies
	 * are less interesting (less likely to be successful).
	 * 
	 * Actual comparison rules/scoring:
	 * 		specific + non-deser + default 	7	1 + 2 + 4
	 * 		non-spec + non-deser + default 	6	0 + 2 + 4
	 * 		specific + deser     + default 	5	1 + 0 + 4
	 * 		non-spec + deser     + default 	4	0 + 0 + 4
	 * 		specific + non-deser + non-def 	3	1 + 2 + 0
	 * 		non-spec + non-deser + non-def 	2	0 + 2 + 0
	 * 		specific + deser     + non-def 	1	1 + 0 + 0
	 * 		non-spec + deser     + non-def 	0	0 + 0 + 0
	 * 
	 * 
	 * @param other The other RMIAttack object to compare to.
	 * @return An int indicating the sorting order.
	 ******************/
	public final int compareTo(RMIAttack other) {
		int thisScore = 0;
		int otherScore = 0;
		
		//Calculate scores
		if(this._isAppSpecific == true) { thisScore += 1; }
		if(this._isDeserAttack == false) { thisScore += 2; }
		if(this._nonDefaultDependency == false) { thisScore += 4; }
		if(other.isAppSpecific() == true) { otherScore += 1; }
		if(other.isDeserAttack() == false) { otherScore += 2; }
		if(other.hasNonDefaultDependencies() == false) { otherScore += 4; }
		
		//Return the difference
		return otherScore - thisScore;
	}
	
	/*******************
	 * Return a string based on the 'compareTo' method, which indicates the
	 * reliability of the attack.
	 * 
	 * @return A string based on the compareTo method indicating the reliability of the attack.
	 ******************/
	public final String getReliabilityIndicator() {
		return "[" + (this._isAppSpecific == true ? "+" : "-") + (this._isDeserAttack == false ? "+" : "-") + (this._nonDefaultDependency == false ? "+" : "-") + "]";
	}
	
	/*******************
	 * Check whether the attack is specific to an RMI application.
	 * 
	 * Most will be, this is more to support the Registry.bind() exploit which
	 * is generic and applies to the RMI registry rather than the underlying
	 * application.
	 * 
	 * @return True if the attack is application specific.
	 ******************/
	public final boolean isAppSpecific() {
		return this._isAppSpecific;
	}
	
	/*******************
	 * Set the application-specific property of the RMIAttack.
	 * 
	 * @param appSpecific True if the attack is application specific, false if it's more generic (such as Registry.bind()).
	 ******************/
	protected final void setAppSpecific(boolean appSpecific) {
		this._isAppSpecific = appSpecific;
	}
	
	/*******************
	 * Check whether the attack targets Java deserialization.
	 * 
	 * Some attacks target insecure use of RMI (e.g. exposed sensitive methods)
	 * whereas others will target Java deserialization and may rely on the
	 * presence of third-party libraries. This method differentiates between
	 * these types of attacks.
	 * 
	 * @return True if the attack targets Java deserialization.
	 ******************/
	public final boolean isDeserAttack() {
		return this._isDeserAttack;
	}
	
	/*******************
	 * Set the is-deser-attack property of the RMIAttack.
	 * 
	 * @param isDeserAttack True if the attack targets Java deserialization.
	 ******************/
	protected final void setIsDeserAttack(boolean isDeserAttack) {
		this._isDeserAttack = isDeserAttack;
	}
	
	/*******************
	 * Check whether a non-default dependency is required for this attack.
	 * 
	 * For example attacks that target Java deserialization generally depend on
	 * the presence of a third-party library which may not be present in the
	 * case of an application framework or application server. In other cases
	 * the target application itself might have suitable POP gadget chains so
	 * a deserialization attack is possible without a non-default dependency.
	 * 
	 * @return True if the attack relies on a dependency that may not be present.
	 ******************/
	public final boolean hasNonDefaultDependencies() {
		return this._nonDefaultDependency;
	}
	
	/*******************
	 * Set the flag indicating that non-default dependencies are required by
	 * this attack.
	 * 
	 * @param nonDefaultDependency True if the attack requires dependencies that may not be present.
	 ******************/
	protected final void setRequiresNonDefaultDependency(boolean nonDefaultDependency) {
		this._nonDefaultDependency = nonDefaultDependency;
	}
	
	/*******************
	 * Get a brief description of this attack.
	 * 
	 * @return A brief description of the attack.
	 ******************/
	public final String getDescription() {
		return this._description;
	}
	
	/*******************
	 * Set a brief description for the RMIAttack.
	 * 
	 * @param description A brief description of the attack.
	 ******************/
	protected final void setDescription(String description) {
		this._description = description;
	}
	
	/*******************
	 * Get a detailed description of this attack.
	 * 
	 * @return A detailed description of the attack.
	 ******************/
	public final String getDetailedDescription() {
		return this._detail;
	}
	
	/*******************
	 * Set a detailed description for the RMIAttack.
	 * 
	 * @param detail A detailed description of the attack.
	 ******************/
	protected final void setDetailedDescription(String detail) {
		this._detail = detail;
	}
	
	/*******************
	 * Get remediation advice for preventing this attack.
	 * 
	 * @return A string containing remediation advice to prevent the attack.
	 ******************/
	public final String getRemediationAdvice() {
		return this._remediation;
	}
	
	/*******************
	 * Set the remediation advice for this RMIAttack.
	 * 
	 * @param remediation Remediation advice to prevent the attack.
	 ******************/
	protected final void setRemediationAdvice(String remediation) {
		this._remediation = remediation;
	}
	
	/*******************
	 * Set the program options field so this attack has access to things like
	 * socket timeout values.
	 * 
	 * @param options The current ProgramOptions object.
	 ******************/
	public final void setProgramOptions(ProgramOptions options) {
		this._options = options;
	}
	
	/*******************
	 * Helper method to prompt the user for input (such as commands to execute
	 * as part of an attack).
	 * 
	 * @param prompt A prompt asking the user for appropriate input.
	 * @param allowEmpty True if an empty response should be allowed. If false then the prompt will repeat until the user provides input.
	 * @return The user's input.
	 * @throws BaRMIeInputException If an IOException occurs whilst reading input from STDIN.
	 ******************/
	protected final String promptUserForInput(String prompt, boolean allowEmpty) throws BaRMIeInputException {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String input = "";
		
		//Enter input loop until we have an acceptable input from the user
		while(input.equals("") == true) {
			//Prompt the user
			System.out.print(prompt);
			
			//Attempt to read a line of input
			try {
				input = br.readLine();
			} catch(IOException ioe) {
				throw new BaRMIeInputException(ioe);
			}
			
			//Break out of the loop if empty input is allowed
			if(allowEmpty == true) {
				break;
			}
		}
		
		//Return the user input
		return input;
	}
	
	/*******************
	 * Helper method to prompt the user for input (such as commands to execute
	 * as part of an attack), with a default response if the user does not
	 * provide any input.
	 * 
	 * @param prompt A prompt asking the user for appropriate input.
	 * @param defaultResponse The default response if the user's input is blank.
	 * @return The user's input or the default response.
	 * @throws BaRMIeInputException If an IOException occurs whilst reading input from STDIN.
	 ******************/
	protected final String promptUserForInputWithDefault(String prompt, String defaultResponse) throws BaRMIeInputException {
		String input;
		
		//Prompt the user for input and allow empty inputs
		input = this.promptUserForInput(prompt, true);
		
		//Return the user's input, or the default response if the user didn't provide any input
		return (input.equals("") ? defaultResponse : input);
	}
	
	/*******************
	 * Helper method to retrieve a remote object reference from the given RMI
	 * endpoint.
	 * 
	 * If the object being retrieved was bound to localhost or 127.0.0.1 and
	 * the RMI registry is not on localhost then this method will automatically
	 * check whether the object's port can be reached on the registry host. If
	 * it can, then a port forwarder is started to forward traffic on the local
	 * port to the RMI registry host. This enables objects to be attacked
	 * remotely when the were only bound to local host.
	 * 
	 * If a remote serialVersionUID does not match the relevant local
	 * serailVersionUID then this method delegates to the method
	 * getRemoteObjectWithUIDHack(), which proxies the RMI registry connection
	 * in order to modify returned serialVersionUID fields to match those of
	 * local classes. This is a hack which won't work in all cases but this
	 * enables BaRMIe to support multiple versions of target applications. This
	 * is because different versions of the class may have different values for
	 * the serialVersionUID field, however the actual interface and the way we
	 * interact with that class/object does not change. Modifying the returned
	 * serialVersionUID effectively "tricks" the local JVM into believing that
	 * the two classes are the same, allowing the remote method invocation to
	 * be performed.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 * @param objectName The name of the object to look up.
	 * @return The remote object reference.
	 * @throws BaRMIeGetObjectException If there was a problem retrieving the requested object.
	 ******************/
	protected Object getRemoteObject(RMIEndpoint ep, String objectName) throws BaRMIeGetObjectException {
		Registry reg;
		Object obj;
		
		//Start port forwarding if necessary
		this.startPortForwarding(ep, objectName);
		
		//Get a reference to the target RMI registry
		try {
			reg = LocateRegistry.getRegistry(ep.getEndpoint().getHost(), ep.getEndpoint().getPort());
		} catch(RemoteException rex) {
			throw new BaRMIeGetObjectException("Failed to create a reference to the target RMI registry.", rex);
		}
		
		//Get the requested object
		try {
			obj = reg.lookup(objectName);
		} catch(UnmarshalException ue) {
			//An Unmarshal exception might occur if the local class has a different serialVersionUID to the remote one, use a hack to modify the serialVersionUID if this is the case...
			if(ue.getCause() instanceof InvalidClassException && ue.getCause().toString().contains("local class incompatible: stream classdesc serialVersionUID = ")) {
				//Attempt to get the object again, this time using a hack to fix the serialVersionUID field
				obj = this.getRemoteObjectWithUIDHack(ep, objectName);
			} else {
				//Unknown exception
				throw new BaRMIeGetObjectException("Failed to lookup the object '" + objectName + "'.", ue);
			}
		} catch(NotBoundException nbe) {
			throw new BaRMIeGetObjectException("The object '" + objectName + "' is not bound to the target RMI registry.", nbe);
		} catch(RemoteException rex) {
			throw new BaRMIeGetObjectException("Failed to lookup the object '" + objectName + "'.", rex);
		}
		
		//Return the requested object
		return obj;
	}
	
	/*******************
	 * Hack to retrieve an RMI object where the remote serialVersionUID does
	 * not match the serialVersionUID of the local class.
	 * 
	 * Here we request the remote object through a proxy. When the object data
	 * comes back over the proxy, we update serialVersionUID fields at the
	 * network level so that they match those of the local classes.
	 * 
	 * This hack makes BaRMIe attacks compatible with multiple versions of
	 * target applications without having to recompile the code with the
	 * required serialVersionUID.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 * @param objectName The name of the object to look up.
	 * @return The remote object reference.
	 * @throws BaRMIeGetObjectException If there was a problem retrieving the requested object.
	 ******************/
	private Object getRemoteObjectWithUIDHack(RMIEndpoint ep, String objectName) throws BaRMIeGetObjectException {
		RMIObjectUIDFixingProxy proxy = null;
		Registry reg;
		Object obj;
		
		try {
			//Start a UID fixing proxy
			proxy = new RMIObjectUIDFixingProxy(InetAddress.getByName(ep.getEndpoint().getHost()), ep.getEndpoint().getPort(), this._options);
			proxy.startProxy();
			
			//Get an RMI registry reference which points at our UID fixing proxy
			reg = LocateRegistry.getRegistry(proxy.getServerListenAddress().getHostAddress(), proxy.getServerListenPort());
			
			//Request the remote object through the proxy and return it
			obj = reg.lookup(objectName);
			return obj;
		} catch(Exception ex) {
			throw new BaRMIeGetObjectException("Failed to lookup a remote object via RMIObjectUIDFixingProxy.", ex);
		} finally {
			//Stop proxy
			if(proxy != null) {
				proxy.stopProxy(true);
			}
		}
	}
	
	/*******************
	 * Start port forwarding for a remote object if necessary.
	 * 
	 * If the RMI registry is NOT listening on local host, and the given remote
	 * object IS listening on local host, then this method checks whether a
	 * connection can be established to the object on the RMI registry host and
	 * if so a port forwarder is started on the same local port.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 * @param objectName The name of the object to look up.
	 ******************/
	protected void startPortForwarding(RMIEndpoint ep, String objectName) throws BaRMIeGetObjectException {
		PortForwarder forwarder;
		
		//If the target RMI registry is not on local host, but the target object is, then set up port forwarding
		if(ep.getEndpoint().getHost().startsWith("127.") == false && ep.getEndpoint().getHost().equalsIgnoreCase("localhost") == false) {
			//Find the target object and check if it's bound to local host
			for(RMIObject rmiObj: ep.getExposedObjects()) {
				if(rmiObj.getObjectEndpoint().getHost().startsWith("127.") || rmiObj.getObjectEndpoint().getHost().equalsIgnoreCase("localhost")) {
					//Remote object is bound to local host, can we reach the target port on the registry host?
					System.out.println("[~] Remote object is bound to local host, testing external connectivity...");
					if(this.testConnection(ep.getEndpoint().getHost(), rmiObj.getObjectEndpoint().getPort()) == true) {
						try {
							//We can connect to the target, attempt to start a port forwarding proxy
							forwarder = new PortForwarder(InetAddress.getByName(ep.getEndpoint().getHost()), rmiObj.getObjectEndpoint().getPort(), this._options);
							forwarder.startProxy();
							
							//Add the proxy to a list for cleanup after the attack has completed
							this._proxies.add(forwarder);
							
							//Print port forwarding status
							System.out.println("[+] Object appears to be exposed remotely, a port forwarder has been started.");
							System.out.println("[+] Local TCP port " + rmiObj.getObjectEndpoint().getPort() + " is being forwarded to " + ep.getEndpoint().getHost() + ":" + rmiObj.getObjectEndpoint().getPort());
						} catch(Exception ex) {
							throw new BaRMIeGetObjectException("Failed to start a port forwarder for the remote object.", ex);
						}
					} else {
						//Unable to connect to the object port on the non-local registry host, print a warning
						System.out.println("[~] Warning: connection to " + ep.getEndpoint().getHost() + ":" + rmiObj.getObjectEndpoint().getPort() + " failed, object lookup may fail");
					}
				}
			}
		}
	}
	
	/*******************
	 * Test whether a TCP connection can be established to the given host and
	 * port.
	 * 
	 * Used, for example, when a remote object is bound to local host. The
	 * object may still be exposed externally, however, port forwarding will
	 * need to be used in order to access the remote object.
	 * 
	 * @param host The host to connect to.
	 * @param port The port to connect to.
	 * @return True if the connection succeeded, false otherwise.
	 ******************/
	protected boolean testConnection(String host, int port) {
		Socket sock = null;
		
		//Attempt to connect to the target
		try {
			sock = new Socket();
			sock.connect(new InetSocketAddress(host, port), this._options.getSocketTimeout());
		} catch(Exception ex) {
			//An exception occurred, failed to connect
			return false;
		} finally {
			//Make sure the connection is closed
			if(sock != null) {
				try { sock.close(); } catch(Exception ex) { }
			}
		}
		
		//Success
		return true;
	}
	
	/*******************
	 * Helper method to write a file, such as one retrieved from a vulnerable
	 * RMI service.
	 * 
	 * @param filename The filename to write to.
	 * @param contents The file contents to write.
	 * @throws BaRMIeWriteFileException If an exception occurred whilst attempting to write the file.
	 ******************/
	protected void writeFile(String filename, byte[] contents) throws BaRMIeWriteFileException {
		FileOutputStream file = null;
		
		//Attempt to write the file
		try {
			file = new FileOutputStream(filename);
			file.write(contents);
		} catch(IOException ioe) {
			throw new BaRMIeWriteFileException("Failed to write the file '" + filename + "'.", ioe);
		} finally {
			if(file != null) {
				try { file.close(); } catch(Exception e) {}
			}
		}
	}
	
	/*******************
	 * Helper method to check if a file exists, for example to verify that a
	 * file was downloaded from a vulnerable RMI service.
	 * 
	 * @param filename The filename to check for.
	 * @return True if the file exists
	 ******************/
	protected boolean fileExists(String filename) {
		return new File(filename).exists();
	}
	
	/*******************
	 * Generate a random alphanumeric string which is 8-32 characters long.
	 * 
	 * @return A random string.
	 ******************/
	protected String generateRandomString() {
		SecureRandom sr = new SecureRandom();
		char[] chars = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();
		String out = "";
		int len;
		
		//Build a random string
		len = sr.nextInt(24) + 8;
		for(int i = 0; i < len; ++i) {
			out = out + chars[sr.nextInt(chars.length)];
		}
		
		//Return the string
		return out;
	}
}
