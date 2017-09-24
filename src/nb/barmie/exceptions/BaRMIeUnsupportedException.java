package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if an unsupported executeAttack()
 * method is called on an RMIAttack object.
 * 
 * E.g. if a deserialization attack is executed without a
 * deserialization payload.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeUnsupportedException extends BaRMIeException {
	public BaRMIeUnsupportedException(String message) {
		super(message);
	}
}
