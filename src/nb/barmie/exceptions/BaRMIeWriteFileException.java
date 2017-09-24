package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if the writeFile method of RMIAttack
 * fails for some reason.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeWriteFileException extends BaRMIeException {
	public BaRMIeWriteFileException(String message, Throwable cause) {
		super(message, cause);
	}
}
