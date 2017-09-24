package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if an exception occurs during proxy
 * server startup - for example if there's an IOException
 * whilst creating the ServerSocket.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeProxyStartupException extends BaRMIeException {
	public BaRMIeProxyStartupException(String message, Throwable cause) { super(message, cause); }
}
