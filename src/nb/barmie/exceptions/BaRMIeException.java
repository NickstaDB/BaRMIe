package nb.barmie.exceptions;

/***********************************************************
 * Base class for exceptions thrown by BaRMIe.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public abstract class BaRMIeException extends Exception {
	public BaRMIeException(String message) {
		super(message);
	}
	
	public BaRMIeException(String message, Throwable cause) {
		super(message, cause);
	}
}
