package nb.barmie.exceptions;

/***********************************************************
 * Exception thrown if the contents of a ReplyData packet
 * captured through the RMI registry proxy do not appear
 * to be valid.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class BaRMIeInvalidReplyDataPacketException extends BaRMIeException {
	public BaRMIeInvalidReplyDataPacketException(String message) {
		super(message);
	}
	
	public BaRMIeInvalidReplyDataPacketException(String message, Throwable cause) {
		super(message, cause);
	}
}
