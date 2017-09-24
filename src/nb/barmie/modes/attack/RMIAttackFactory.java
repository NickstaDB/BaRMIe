package nb.barmie.modes.attack;

import java.util.ArrayList;
import nb.barmie.modes.enumeration.RMIEndpoint;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * RMI attack factory class.
 * 
 * Essentially maintains a list of all supported RMI
 * attacks and the classes which implement them.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RMIAttackFactory {
	/*******************
	 * Properties
	 ******************/
	private static final ArrayList<RMIAttack> _attacks;	//All RMI attack objects
	
	/*******************
	 * Initialise the list of supported RMI attacks
	 ******************/
	static {
		//Create the list of RMI attacks
		_attacks = new ArrayList<RMIAttack>();
		
		//Add all known attacks to the list
		_attacks.add(new nb.barmie.modes.attack.attacks.Java.IllegalRegistryBind());							//RMI Registry.bind() deserialization attack.
		_attacks.add(new nb.barmie.modes.attack.attacks.SpringFramework.RmiInvocationHandlerDeser());			//Spring RMI Remoting invoke() deserialization attack
		_attacks.add(new nb.barmie.modes.attack.attacks.SpringFramework.Spring2RmiInvocationHandlerDeser());	//Spring 2 RMI Remoting invoke() deserialization attack
		_attacks.add(new nb.barmie.modes.attack.attacks.Axiom.DeleteFile());									//AxiomSL delete file
		_attacks.add(new nb.barmie.modes.attack.attacks.Axiom.ListFiles());										//AxiomSL list files
		_attacks.add(new nb.barmie.modes.attack.attacks.Axiom.ReadFile());										//AxiomSL read file
		_attacks.add(new nb.barmie.modes.attack.attacks.Axiom.WriteFile());										//AxiomSL write file
	}
	
	/*******************
	 * Attacks may need access to things like socket timeout options so this
	 * method passes the current ProgramOptions object to each known attack.
	 * 
	 * @param options The current ProgramOptions object.
	 ******************/
	public static void setProgramOptions(ProgramOptions options) {
		for(RMIAttack att: _attacks) {
			att.setProgramOptions(options);
		}
	}
	
	/*******************
	 * Clean up all attacks.
	 ******************/
	public static void cleanUp() {
		for(RMIAttack att: _attacks) {
			att.cleanUp();
		}
	}
	
	/*******************
	 * Find all attacks that can target a given RMI endpoint.
	 * 
	 * @param ep The enumerated RMI endpoint.
	 * @return An ArrayList of RMIAttack objects that can target the given endpoint.
	 ******************/
	public static ArrayList<RMIAttack> findAttacksForEndpoint(RMIEndpoint ep) {
		ArrayList<RMIAttack> attacks = new ArrayList<RMIAttack>();
		
		//Find all RMI attacks that can target the given endpoint
		for(RMIAttack a: _attacks) {
			if(a.canAttackEndpoint(ep)) {
				attacks.add(a);
			}
		}
		
		//Return the list of attacks for the given endpoint
		return attacks;
	}
}
