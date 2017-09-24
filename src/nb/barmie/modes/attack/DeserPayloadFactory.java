package nb.barmie.modes.attack;

import java.util.ArrayList;
import nb.barmie.modes.enumeration.RMIEndpoint;

/***********************************************************
 * Deserialization payload factory class.
 * 
 * Essentially maintains a list of all supported Java
 * deserialization payloads and the classes/objects
 * implementing them.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class DeserPayloadFactory {
	/*******************
	 * Properties
	 ******************/
	private static final ArrayList<DeserPayload> _payloads; //All deserialization payloads
	
	/*******************
	 * Initialise the list of supported deserialization payloads
	 ******************/
	static {
		//Create the list of deserialization payloads
		_payloads = new ArrayList<DeserPayload>();
		
		//Add all supported payloads to the list
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.CommonsCollectionsPayload1());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.CommonsCollectionsPayload2());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.GroovyPayload1());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.GroovyPayload2());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.JBossInterceptorsPayload1());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.ROMEPayload1());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.ROMEPayload2());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.RhinoPayload1());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.RhinoPayload2());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.RhinoPayload3());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.RhinoPayload4());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.RhinoPayload5());
		_payloads.add(new nb.barmie.modes.attack.deser.payloads.RhinoPayload6());
	}
	
	/*******************
	 * Find all deserialization payloads that affect the given RMI endpoint.
	 * 
	 * This won't always work as it depends on remote classes being annotated
	 * with CLASSPATH jar files. If these annotations aren't present, as is
	 * often the case, then all payloads can be attempted (or attack/target
	 * specific payloads can be used).
	 * 
	 * @param ep The enumerated RMI endpoint.
	 * @return An ArrayList of DeserPayload objects that should affect the given endpoint.
	 ******************/
	public static ArrayList<DeserPayload> findGadgetsForEndpoint(RMIEndpoint ep) {
		ArrayList<DeserPayload> payloads = new ArrayList<DeserPayload>();
		
		//Find all deserialization payloads that can target the given endpoint
		for(DeserPayload p: _payloads) {
			if(p.doesAffectEndpoint(ep)) {
				payloads.add(p);
			}
		}
		
		//Return the list of deserialization payloads that affect the given endpoint
		return payloads;
	}
	
	/*******************
	 * Get a list of all known deserialization payloads.
	 * 
	 * @return An ArrayList of DeserPayload objects.
	 ******************/
	public static ArrayList<DeserPayload> getAllPayloads() {
		return _payloads;
	}
}
