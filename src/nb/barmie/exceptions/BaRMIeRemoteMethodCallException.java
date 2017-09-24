package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if there was a problem calling a remote
 * method during an attack.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeRemoteMethodCallException extends BaRMIeException {
	public BaRMIeRemoteMethodCallException(String message, Throwable cause) {
		super(message, cause);
	}
}
