package nb.barmie.util;

/***********************************************************
 * Helper class used to debug strange responses by dumping
 * packet bytes as hex+ASCII.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class DataDumper {
	/*******************
	 * Dump an array of bytes to a string as hex+ASCII.
	 * 
	 * @param data The data to dump.
	 * @return A string containing the hex+ASCII representation of the data.
	 ******************/
	public static String generateHexAsciiDumpString(byte[] data) {
		StringBuilder dump = new StringBuilder(data.length * 5);
		StringBuilder curRowAscii = new StringBuilder(16);
		
		//Loop over the supplied data building a hex and ASCII dump
		for(int i = 0; i < data.length; ++i) {
			//Dump a hex byte
			dump.append(String.format("%02x", data[i]));
			dump.append(" ");
			
			//Generate an ASCII byte
			if(((int)data[i]) >= 0x20 && ((int)data[i]) <= 0x7e) {
				//Printable byte
				curRowAscii.append((char)data[i]);
			} else {
				//Non-printable byte, use . as a placeholder
				curRowAscii.append(".");
			}
			
			//Handle padding and row ends
			if(curRowAscii.length() == 8) {
				//Generate an extra couple of padding spaces at 8 bytes for readability
				dump.append("  ");
			} else if(curRowAscii.length() == 16) {
				//Dump the ASCII, start a nenw row, and reset the ASCII string
				dump.append("    ");
				dump.append(curRowAscii.toString());
				dump.append("\n");
				curRowAscii.setLength(0);
			}
		}
		
		//Handle dumping of the remaining ASCII
		if(curRowAscii.length() > 0) {
			//Calculate and dump padding for the final ASCII chunk
			dump.append(new String(new char[(3 * (16 - curRowAscii.length())) + 4]).replace('\0', ' '));
			
			//Additional 2 characters of padding if the current ASCII chunk less than 8 bytes in length
			if(curRowAscii.length() < 8) {
				dump.append("  ");
			}
			
			//Dump final ASCII chunk
			dump.append(curRowAscii.toString());
		}
		
		//Append a new line to the dump
		dump.append("\n");
		
		//Return the result of the data dump
		return dump.toString();
	}
}
