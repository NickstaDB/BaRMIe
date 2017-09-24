package nb.barmie.modes.attack;

import java.util.ArrayList;
import java.util.Collections;
import nb.barmie.modes.enumeration.RMIEndpoint;

/***********************************************************
 * Container class for RMI target data - contains an RMI
 * endpoint along with any RMI attacks and deserialization
 * payloads that apply to the endpoint.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RMITargetData {
	/*******************
	 * Properties
	 ******************/
	private RMIEndpoint _endpoint;				//The RMI endpoint
	private ArrayList<RMIAttack> _attacks;		//EMI attacks affecting this endpoint
	private ArrayList<DeserPayload> _payloads;	//Deserialization payloads affecting this endpoint
	
	/*******************
	 * Initialise the RMITargetData object based on enumeration results.
	 * 
	 * @param endpoint The enumerated RMI endpoint.
	 ******************/
	public RMITargetData(RMIEndpoint endpoint) {
		this._endpoint = endpoint;
		this._attacks = RMIAttackFactory.findAttacksForEndpoint(this._endpoint);
		this._payloads = DeserPayloadFactory.findGadgetsForEndpoint(this._endpoint);
		
		//Sort the available attacks
		Collections.sort(this._attacks);
	}
	
	/*******************
	 * Check if we have any supported attacks for the endpoint.
	 * 
	 * @return True if we have attacks for the endpoint.
	 ******************/
	public boolean hasSupportedAttacks() {
		return (this._attacks.size() > 0);
	}
	
	/*******************
	 * Check if any of the supported attacks for this endpoint are
	 * deserialization attacks.
	 * 
	 * @return True if any of the attacks for this endpoint are deserialization attacks.
	 ******************/
	public boolean hasDeserializationAttacks() {
		for(RMIAttack a: this._attacks) {
			if(a.isDeserAttack() == true) {
				return true;
			}
		}
		return false;
	}
	
	/*******************
	 * Check if we have any deserialization payloads that likely affect this
	 * endpoint (based on leaked CLASSPATH data).
	 * 
	 * @return True if we have any deserialization payloads affecting this endpoint.
	 ******************/
	public boolean hasAffectedLibs() {
		return (this._payloads.size() > 0);
	}
	
	/*******************
	 * Return a string representation of this target.
	 * 
	 * The output includes the host:port, reliability of the best available
	 * attack, and states whether known deserialization attacks and payloads
	 * were identified.
	 * 
	 * @return A string describing the target and available attacks/payloads.
	 ******************/
	public String getDetailString() {
		String out;
		
		//Host and port
		out = this._endpoint.getEndpoint().toString();
		
		//Attack details
		if(this._attacks.size() > 0) {
			//Add reliability of best attack
			out += " Reliability " + this._attacks.get(0).getReliabilityIndicator();
			
			//Add details of available deserialization attacks/payloads
			out += ", Deser attack ";
			if(this.hasDeserializationAttacks() == true) {
				out += "[Y], payload ";
				if(this.hasAffectedLibs() == true) {
					out += "[Y]";
				} else {
					out += "[?]"; //Question mark as deserialization payloads cannot always be detected
				}
			} else {
				out += "[N]";
			}
		} else {
			out += " No attacks available.";
		}
		
		//Return the target details
		return out;
	}
	
	/*******************
	 * Getters
	 ******************/
	public RMIEndpoint getEndpoint() { return this._endpoint; }
	public ArrayList<RMIAttack> getAttacks() { return this._attacks; }
	public ArrayList<DeserPayload> getDeserPayloads() { return this._payloads; }
}
