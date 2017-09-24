package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if a deserialization attack fails for
 * some reason.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeDeserAttackException extends BaRMIeException {
	public BaRMIeDeserAttackException(String message, Throwable cause) {
		super(message, cause);
	}
}
