package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if a DeliveryMethod has problems with
 * proxying a remote object or remote method call.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeObjectProxyException extends BaRMIeException {
	public BaRMIeObjectProxyException(String message, Throwable cause) {
		super(message, cause);
	}
}
