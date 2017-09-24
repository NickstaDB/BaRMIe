package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if there was an IOException whilst
 * reading from STDIN.
 * 
 * I.e. when an attack class is prompting for attack
 * input/options.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeInputException extends BaRMIeException {
	public BaRMIeInputException(Throwable cause) {
		super("An IOException occurred whilst reading from STDIN.", cause);
	}
}
