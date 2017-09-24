package nb.barmie.modes.attack;

import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.modes.enumeration.RMIEndpoint;

/***********************************************************
 * DeserPayload base class.
 * 
 * All deserialization payloads must extend this class and implement the
 * following method:
 *	getBytes(String cmd, int handleCorrection): Generate and return the payload bytes to execute a given command.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public abstract class DeserPayload {
	/*******************
	 * Constants
	 ******************/
	protected final String REMEDIATION_NO_FIX = "No fix currently available. Consider removing the library from the CLASSPATH of the RMI service.";
	
	/*******************
	 * Properties
	 ******************/
	private String _name;				//A short name for the payload
	private String[] _affectedJars;		//An array of JAR filenames that are affected by this deserialization payload
	private String _description;		//A brief one-liner description of the payload
	private String _remediationAdvice;	//Remediation advice
	
	/*******************
	 * Default constructor, defaults all properties
	 ******************/
	public DeserPayload() {
		this._name = "";
		this._affectedJars = null;
		this._description = "";
		this._remediationAdvice = "";
	}
	
	/*******************
	 * Check if this payload affects the given RMI endpoint.
	 * 
	 * Note that this won't always return true when the endpoint is affected.
	 * The detection relies on the exposed objects being annotated with the
	 * Java CLASSPATH. If this information isn't available the endpoint may
	 * still be vulnerable.
	 * 
	 * @param ep An enumerated endpoint
	 * @return True if this deserialization payload affects the endpoint.
	 ******************/
	public final boolean doesAffectEndpoint(RMIEndpoint ep) {
		for(String jar: this._affectedJars) {
			if(ep.hasJar(jar)) {
				return true;
			}
		}
		return false;
	}
	
	/*******************
	 * Generate the payload bytes to execute the given command line.
	 * 
	 * When a payload is injected into a remote method invocation packet, the
	 * packet may have other objects (or method parameters) prior to the
	 * payload injection point. Any such elements in the serialized data for
	 * the method call will result in the handle value for TC_REFERENCE
	 * elements being incremented. As a result, any TC_REFERENCE elements
	 * within the payload itself may have incorrect handle values (i.e. the
	 * first handle in the payload data should be 0x007e0000, if there's a
	 * handle already in the packet then that will also have the handle value
	 * 0x007e0000 and a reference within the payload to 0x007e0000 will point
	 * at the wrong content element, so to correct this we need to add 1 to
	 * all TC_REFERENCE elements in the payload bytes).
	 * 
	 * @param cmd The operating system command to execute.
	 * @param refCorrection The amount to correct TC_REFERENCE handles by (see note above).
	 * @return An array of bytes making up the deserialization payload.
	 ******************/
	public abstract byte[] getBytes(String cmd, int refCorrection) throws BaRMIeException;
	
	/*******************
	 * Get the payload name.
	 * 
	 * @return The name of the payload.
	 ******************/
	public final String getName() {
		return this._name;
	}
	
	/*******************
	 * Set the payload name.
	 * 
	 * @param name The name of the payload.
	 ******************/
	protected final void setName(String name) {
		this._name = name;
	}
	
	/*******************
	 * Get the array of jar files affected by this deserialization payload.
	 * 
	 * @return An array of strings which are jar file names affected by this payload.
	 ******************/
	public final String[] getAffectedJars() {
		return this._affectedJars;
	}
	
	/*******************
	 * Set the array of jar files that are affected by this deserialization payload.
	 * 
	 * @param affectedJars An array of strings which are the jar files affected by this payload.
	 ******************/
	protected final void setAffectedJars(String[] affectedJars) {
		this._affectedJars = affectedJars;
	}
	
	/*******************
	 * Get a brief description of this payload.
	 * 
	 * @return A brief description of this payload.
	 ******************/
	public final String getDescription() {
		return this._description;
	}
	
	/*******************
	 * Set a brief description for the payload.
	 * 
	 * @param description A brief description of the payload.
	 ******************/
	protected final void setDescription(String description) {
		this._description = description;
	}
	
	/*******************
	 * Get remediation advice for this payload.
	 * 
	 * @return Remediation advice that may help in defending against this payload.
	 ******************/
	public final String getRemediationAdvice() {
		return this._remediationAdvice;
	}
	
	/*******************
	 * Set remediation advice for the payload.
	 * 
	 * @param remediationAdvice Remediation advice that may help to defend against this payload.
	 ******************/
	protected final void setRemediationAdvice(String remediationAdvice) {
		this._remediationAdvice = remediationAdvice;
	}
	
	/*******************
	 * Helper method to convert a string of hex-ascii-encoded bytes into a
	 * corresponding array of bytes.
	 * 
	 * @param hexStr A string of hex-encoded bytes.
	 * @return The resulting byte array.
	 ******************/
	protected final byte[] hexStrToByteArray(String hexStr) {
		byte[] data;
		
		//Create the byte array
		data = new byte[hexStr.length() / 2];
		
		//Convert the hex string to bytes
		for(int i = 0; i < hexStr.length(); i += 2) {
			data[i / 2] = (byte)((Character.digit(hexStr.charAt(i), 16) << 4) + Character.digit(hexStr.charAt(i + 1), 16));
		}
		
		//Return the resulting byte array
		return data;
	}
	
	/*******************
	 * Helper method to convert a string to a Utf8 byte array (2-byte length
	 * followed by string bytes).
	 * 
	 * @param val The string to convert to a byte array.
	 * @return The resulting byte array.
	 ******************/
	protected final byte[] stringToUtf8ByteArray(String val) {
		byte[] outBytes = new byte[val.length() + 2];
		byte[] strBytes = val.getBytes();
		
		//Build the output byte array
		outBytes[0] = (byte)((strBytes.length >> 8) & 0xff);
		outBytes[1] = (byte)(strBytes.length & 0xff);
		for(int i = 0; i < strBytes.length; ++i) {
			outBytes[i + 2] = strBytes[i];
		}
		
		//Return the output bytes
		return outBytes;
	}
	
	/*******************
	 * Helper method to convert a short to a byte array.
	 * 
	 * @param val The short to convert to a byte array.
	 * @return The resulting byte array.
	 ******************/
	protected final byte[] shortToByteArray(short val) {
		return new byte[] {
			(byte)((val >> 8) & 0xff),
			(byte)( val       & 0xff)
		};
	}
	
	/*******************
	 * Helper method to convert an int to a byte array.
	 * 
	 * @param val The int to convert to a byte array.
	 * @return The resulting byte array.
	 ******************/
	protected final byte[] intToByteArray(int val) {
		return new byte[] {
			(byte)((val >> 24) & 0xff),
			(byte)((val >> 16) & 0xff),
			(byte)((val >>  8) & 0xff),
			(byte)( val        & 0xff)
		};
	}
	
	/*******************
	 * Helper method to correct the handle values of TC_REFERENCE elements in
	 * the given byte array by adding a given offset to each.
	 * 
	 * The starting value for handles in a serialization stream is 0x7e 00 00.
	 * If a deserialization payload is injected into a serialization stream
	 * that already contains an object with a handle value then any referenced
	 * handles within that payload must be updated accordingly so that they
	 * still refer to handles within the payload, rather than handles within
	 * the stream in which the payload is injected.
	 * 
	 * Note that this is a hacky method that identifies TC_REFERENCE elements
	 * by the byte sequence 0x71 00 7e and won't work if there are more than
	 * 65,535 handles in the stream, or if this byte sequence appears elsewhere
	 * in a payload byte stream.
	 * 
	 * @param original The original payload stream bytes to correct.
	 * @param correction The value to add to each handle value within the payload.
	 * @return A new byte array containing the corrected TC_REFERENCE handle values.
	 ******************/
	protected final byte[] fixReferences(byte[] original, int correction) {
		byte[] fixed = new byte[original.length];
		int refHandle;
		
		//Copy the given bytes but correct reference handle values as required
		for(int i = 0; i < original.length; ++i) {
			//Check if there are enough bytes left in the original to contain a TC_REFERENCE
			if(i < (original.length - 5)) {
				//Look for a TC_REFERENCE at this offset
				if(original[i] == (byte)0x71 && original[i + 1] == (byte)0x00 && original[i + 2] == (byte)0x7e) {
					//Get the low-word of the reference handle
					refHandle = (original[i + 3] << 8) + ((original[i + 4]) & 0xff);
					
					//Correct it
					refHandle = refHandle + correction;
					
					//Copy the reference to the fixed byte array and skip over the bytes in the original
					fixed[i++] = (byte)0x71;
					fixed[i++] = (byte)0x00;
					fixed[i++] = (byte)0x7e;
					fixed[i++] = (byte)((refHandle >> 8) & 0xff);
					fixed[i] = (byte)(refHandle & 0xff);
				} else {
					//Copy the byte straight across
					fixed[i] = original[i];
				}
			} else {
				//Copy the byte straight across
				fixed[i] = original[i];
			}
		}
		
		//Return the fixed payload bytes
		return fixed;
	}
}
