package nb.barmie.net.proxy.thread;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;

/***********************************************************
 * A proxy thread that modifies the serialVersionUID of
 * object references returned by an RMI registry so that
 * the serialVersionUID matches the local class.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class UIDFixingProxyThread extends ProxyThread {
	/*******************
	 * Construct the proxy thread.
	 * 
	 * @param srcSocket The source socket.
	 * @param dstSocket The destination socket.
	 ******************/
	public UIDFixingProxyThread(Socket srcSocket, Socket dstSocket) {
		super(srcSocket, dstSocket);
	}
	
	/*******************
	 * Look for remote object references and fix serialVersionUID fields to
	 * match the serialVersionUID of matching local classes.
	 * 
	 * @param data The data received from the source socket.
	 * @return The data to write to the destination socket.
	 ******************/
	public ByteArrayOutputStream handleData(ByteArrayOutputStream data) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		String className;
		Class clazz;
		long localSerialVersionUID;
		int classNameLength;
		byte[] dataBytes;
		
		//Get the packet bytes
		dataBytes = data.toByteArray();
		
		//Check if this is an RMI ReplyData packet
		if(dataBytes[0] == (byte)0x51) {
			//Copy bytes to the output stream, checking for serialized TC_CLASSDESC elements as we go
			for(int i = 0; i < dataBytes.length; ++i) {
				//Check for 0x72 which identifies a TC_CLASSDESC element
				if(dataBytes[i] == (byte)0x72) {
					//Possible TC_CLASSDESC, attempt to read the class name
					if((i + 2) < dataBytes.length) {
						//There are enough bytes in the packet after the current offset for the length of the class name, read the length of the class name
						classNameLength = ((dataBytes[i + 1] << 8) & 0xff00) + (dataBytes[i + 2] & 0xff);
						
						//Check if there are enough bytes in the packet for the class name and serialVersionUID...
						if((i + 2 + classNameLength + 8) < dataBytes.length) {
							//Read the class name
							className = new String(dataBytes, i + 3, classNameLength);
							
							//Don't process JDK classes (this won't catch all, but it will catch the most common ones...)
							if(className.startsWith("java") == false) {
								//Attempt to fix the serialVersionUID...
								try {
									//Attempt to load the class
									clazz = Class.forName(className);
									
									//Attempt to read the local serialVersionUID field
									localSerialVersionUID = clazz.getDeclaredField("serialVersionUID").getLong(null);
									
									//Write the class description data to the output stream, replacing the serialVersionUID field
									out.write((byte)0x72);
									out.write((byte)((classNameLength & 0xff00) >> 8));
									out.write((byte)(classNameLength & 0xff));
									out.write(className.getBytes());
									out.write((byte)((localSerialVersionUID & 0xff00000000000000L) >> 56));
									out.write((byte)((localSerialVersionUID &   0xff000000000000L) >> 48));
									out.write((byte)((localSerialVersionUID &     0xff0000000000L) >> 40));
									out.write((byte)((localSerialVersionUID &       0xff00000000L) >> 32));
									out.write((byte)((localSerialVersionUID &         0xff000000 ) >> 24));
									out.write((byte)((localSerialVersionUID &           0xff0000 ) >> 16));
									out.write((byte)((localSerialVersionUID &             0xff00 ) >>  8));
									out.write((byte)(localSerialVersionUID &                0xff ));
									
									//Fix the packet offset so that the class description data is not copied to the output packet twice
									i += 10 + classNameLength;
								} catch(IOException | IllegalAccessException | NoSuchFieldException | ClassNotFoundException ex) {
									//Class not found, just copy the current byte over to the output stream
									out.write((byte)dataBytes[i]);
								}
							} else {
								out.write((byte)dataBytes[i]);
							}
						} else {
							out.write((byte)dataBytes[i]);
						}
					} else {
						//Not enough data left in the packet, copy a byte across
						out.write((byte)dataBytes[i]);
					}
				} else {
					//Not a TC_CLASSDESC, copy a byte to the output stream
					out.write((byte)dataBytes[i]);
				}
			}
		} else {
			//Not a ReplyData packet, allow it to pass through untouched
			return data;
		}
		
		//Return the modified packet
		return out;
	}
}
