package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if an attack fails for some reason.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeAttackException extends BaRMIeException {
	public BaRMIeAttackException(String message, Throwable cause) {
		super(message, cause);
	}
}
