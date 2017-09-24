package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if an invalid port number is specified
 * for a target.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeInvalidPortException extends BaRMIeException {
	public BaRMIeInvalidPortException(int portNumber) {
		super("The given port number (" + portNumber + ") is not a valid TCP port number.");
	}
}
