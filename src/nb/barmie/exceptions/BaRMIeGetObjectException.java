package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if there was a problem getting an
 * object from an RMI registry during an attack.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeGetObjectException extends BaRMIeException {
	public BaRMIeGetObjectException(String message, Throwable cause) {
		super(message, cause);
	}
}
