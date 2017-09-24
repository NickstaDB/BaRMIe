package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if a proxy is started is started and
 * hasn't been shut down since last starting it.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeProxyAlreadyStartedException extends BaRMIeException {
	public BaRMIeProxyAlreadyStartedException(String message) { super(message); }
}
