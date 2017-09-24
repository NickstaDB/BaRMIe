package axiomsl.server.rmi;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;

/***********************************************************
 * FileBrowserStub for AxiomSL attacks.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public abstract interface FileBrowserStub extends Remote {
	public abstract FileInformation[] listFilesOnServer(String paramString) throws RemoteException;
	public abstract byte[] readFile(String paramString, long paramLong, int paramInt) throws IOException;
	public abstract void writeFile(String paramString, byte[] paramArrayOfByte) throws IOException;
	public abstract boolean deleteFile(String paramString, boolean paramBoolean) throws RemoteException;
	public abstract FileInformation getFileInformation(String paramString) throws RemoteException;
}
