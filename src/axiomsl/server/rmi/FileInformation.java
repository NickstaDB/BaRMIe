package axiomsl.server.rmi;

import java.io.Serializable;

/***********************************************************
 * FileInformation class for AxiomSL attacks.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class FileInformation implements Serializable {
	public static final long serialVersionUID = -1757023938083597173L;
	public String sAbsolutePath;
	public String sFileName;
	public String sPath;
	public boolean bExists;
	public long lLastModified;
	public long lSize;
	public boolean bIsDirectory;
}
