package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if there is a problem generating a
 * deserialization payload.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeDeserPayloadGenerationException extends BaRMIeException {
	public BaRMIeDeserPayloadGenerationException(String message, Throwable cause) {
		super(message, cause);
	}
}
