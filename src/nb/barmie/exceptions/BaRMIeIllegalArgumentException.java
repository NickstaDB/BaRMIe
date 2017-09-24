package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if invalid command line arguments are
 * passed in.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeIllegalArgumentException extends BaRMIeException {
	public BaRMIeIllegalArgumentException(String message) {
		super(message);
	}
	
	public BaRMIeIllegalArgumentException(String message, Throwable cause) {
		super(message, cause);
	}
}
