package nb.barmie.modes.enumeration;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.rmi.NoSuchObjectException;
import java.util.ArrayList;
import java.util.Collections;
import nb.barmie.modes.attack.DeserPayload;
import nb.barmie.modes.attack.DeserPayloadFactory;
import nb.barmie.modes.attack.RMIAttack;
import nb.barmie.modes.attack.RMIAttackFactory;
import nb.barmie.net.TCPEndpoint;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * Task object which enumerates a single RMI registry
 * target before printing out full details.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class EnumerationTask implements Runnable {
	/*******************
	 * Properties
	 ******************/
	private final TCPEndpoint _target;
	private final RMIEnumerator _enumerator;
	private final ProgramOptions _options;
	
	/*******************
	 * Construct the task with a given target and RMI enumerator object.
	 * 
	 * @param target The target to enumerate.
	 * @param rmie The RMI enumerator to use in enumeration.
	 ******************/
	public EnumerationTask(TCPEndpoint target, RMIEnumerator rmie, ProgramOptions options) {
		this._target = target;
		this._enumerator = rmie;
		this._options = options;
	}
	
	/*******************
	 * Main method - enumerate an RMI endpoint and build a string describing
	 * it before printing the results out.
	 ******************/
	public void run() {
		RMIEndpoint ep;
		String output = "";
		ArrayList<RMIAttack> attacks;
		ArrayList<DeserPayload> deserPayloads;
		boolean deserAttackAvailable = false;
		boolean isLocalRegistry = false;
		int oi = 0, ci = 0;
		
		//Enumerate the endpoint
		ep = this._enumerator.enumerateEndpoint(this._target);
		
		//Set the isLocalRegistry flag if the target is localhost
		if(this._target.getHost().startsWith("127.") == true || this._target.getHost().equalsIgnoreCase("localhost")) {
			isLocalRegistry = true;
		}
		
		//Begin output
		if(ep.isRegistry()) {
			output += "RMI Registry at " + this._target.getHost() + ":" + this._target.getPort() + "\n";
			
			//Object details
			output += "Objects exposed: " + ep.getExposedObjects().size() + "\n";
			for(RMIObject o: ep.getExposedObjects()) {
				//Print the object name
				output += "Object " + (++oi) + "\n";
				output += "  Name: " + o.getObjectName() + "\n";
				
				//Print the object endpoint details
				output += "  Endpoint: " + o.getObjectEndpoint().getHost() + ":" + o.getObjectEndpoint().getPort() + "\n";
				if(isLocalRegistry == false && (o.getObjectEndpoint().getHost().startsWith("127.") || o.getObjectEndpoint().getHost().equalsIgnoreCase("localhost"))) {
					//The RMI registry is not on localhost, but the remote object is bound to localhost, check whether it is listening externally
					if(this.testConnection(this._target.getHost(), o.getObjectEndpoint().getPort())) {
						//The remote object is bound to localhost, but appears to be accessible remotely
						output += "  [+] Object is bound to localhost, but appears to be exposed remotely.\n";
					}
				}
				
				//Print class details
				output += "  Classes: " + o.getObjectClasses().size() + "\n";
				for(String className: o.getObjectClasses().keySet()) {
					//Print class header and name
					output += "    Class " + (++ci) + "\n";
					output += "      Classname: " + className + "\n";
					
					//Print string annotations if there are any
					if(o.getStringAnnotations().size() > 0) {
						output += "      String annotations: " + o.getStringAnnotations().size() + "\n";
						for(String a: o.getStringAnnotations()) {
							//Print out the annotation
							output += "        Annotation: " + a + "\n";
						}
					}
				}
			}
			
			//Remote modification details
			if(ep.isRemotelyModifiable()) {
				output += "[+] It appears to be possible to remotely bind/unbind/rebind to this registry\n";
			}
			
			//Reset flag indicating whether a known deserialization attack is available
			deserAttackAvailable = false;
			
			//Retrieve and print known RMI attacks
			output += "\n";
			attacks = RMIAttackFactory.findAttacksForEndpoint(ep);
			if(attacks.size() > 0) {
				//Output the number of deserialization attacks
				output += attacks.size() + " potential attacks identified (+++ = more reliable)\n";
				
				//Sort the attacks in order of reliability and output the details
				Collections.sort(attacks);
				for(RMIAttack rmia: attacks) {
					//Build output
					output += rmia.getReliabilityIndicator() + " " + rmia.getDescription() + "\n";
					
					//Check for deserialization attacks and set flag
					if(deserAttackAvailable == false && rmia.isDeserAttack() == true) {
						deserAttackAvailable = true;
					}
				}
			}
			
			//If there were deserialization attacks, check for supported deserialization payload libraries
			output += "\n";
			if(deserAttackAvailable == true) {
				//Get all Java deserialization payloads affecting the endpoint
				deserPayloads = DeserPayloadFactory.findGadgetsForEndpoint(ep);
				
				//Add some output
				output += deserPayloads.size() + " deserialization gadgets found on leaked CLASSPATH\n";
				
				//Build output for supported gadgets
				if(deserPayloads.size() > 0) {
					for(DeserPayload p: deserPayloads) {
						output += "[+] " + p.getDescription() + "\n";
					}
				} else {
					output += "[~] Gadgets may still be present despite CLASSPATH not being leaked\n";
				}
			}
			
			//Add exceptions to the output
			if(ep.getEnumException() != null) {
				output += "[-] An exception occurred during enumeration.\n";
				output += "    " + ep.getEnumException().toString() + "\n";
			}
		} else if(ep.isObjectEndpoint()) {
			//Add endpoint data to output
			output += this._target.getHost() + ":" + this._target.getPort() + " appears to be an RMI object endpoint, rather than a registry.\n";
			
			//Add exception as long as it's not a NoSuchObjectException
			if(ep.getEnumException() != null && (ep.getEnumException() instanceof NoSuchObjectException) == false) {
				output += "[-] An exception occurred during enumeration.\n";
				output += "    " + ep.getEnumException().toString() + "\n";
			}
		} else {
			//Check for exceptions
			if(ep.getEnumException() != null) {
				//Check for unsupported endpoints
				if(ep.getEnumException().toString().toLowerCase().contains("non-jrmp") || ep.getEnumException().toString().toLowerCase().contains("error during jrmp")) {
					output += this._target.getHost() + ":" + this._target.getPort() + " is non-RMI or RMI over SSL (not currently supported).\n";
					output += "[~] RMI over SSL support will come in a future release!\n";
				}
			}
		}
		
		//Print the enumeration result
		System.out.println(output);
		System.out.flush();
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
}
