package nb.barmie.net.proxy.thread;

import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.util.ArrayList;

/***********************************************************
 * A proxy thread class used to capture the contents of
 * RMI ReplyData packets in order to enable the extraction
 * of remote object details.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ReplyDataCapturingProxyThread extends ProxyThread {
	/*******************
	 * Properties
	 ******************/
	private volatile ArrayList<Byte> _dataBuffer;
	
	/*******************
	 * Construct the proxy thread.
	 * 
	 * @param srcSocket The source socket.
	 * @param dstSocket The destination socket.
	 ******************/
	public ReplyDataCapturingProxyThread(Socket srcSocket, Socket dstSocket) {
		super(srcSocket, dstSocket);
		
		//Create the data buffer
		this._dataBuffer = new ArrayList<Byte>();
	}
	
	/*******************
	 * Buffer data passing through the proxy, ignoring single-byte RMI ping
	 * acknowledgement packets.
	 * 
	 * @param data The data received from the source socket.
	 * @return The data to write to the destination socket.
	 ******************/
	public ByteArrayOutputStream handleData(ByteArrayOutputStream data) {
		byte[] dataBytes;
		
		//Get the data bytes
		dataBytes = data.toByteArray();
		
		//Ignore RMI ping ack packets
		if((dataBytes.length == 1 && dataBytes[0] == 0x53) == false) {
			//Buffer the received data
			for(int i = 0; i < dataBytes.length; ++i) {
				this._dataBuffer.add(dataBytes[i]);
			}
		}
		
		//Return the original data untouched
		return data;
	}
	
	/*******************
	 * Reset the data buffer - called before requesting each remote object to
	 * ensure the buffer only contains details of the next object to be
	 * requested from the RMI registry.
	 ******************/
	public void resetDataBuffer() {
		this._dataBuffer.clear();
	}
	
	/*******************
	 * Get the data buffer for parsing.
	 * 
	 * @return The data buffer containing details of objects requested from the RMI registry.
	 ******************/
	public ArrayList<Byte> getDataBuffer() {
		return this._dataBuffer;
	}
}
