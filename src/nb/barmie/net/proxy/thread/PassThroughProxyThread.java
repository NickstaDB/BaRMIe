package nb.barmie.net.proxy.thread;

import java.io.ByteArrayOutputStream;
import java.net.Socket;

/***********************************************************
 * A proxy thread that writes received data straight out to
 * the destination socket untouched.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class PassThroughProxyThread extends ProxyThread {
	/*******************
	 * Construct the proxy thread.
	 * 
	 * @param srcSocket The source socket.
	 * @param dstSocket The destination socket.
	 ******************/
	public PassThroughProxyThread(Socket srcSocket, Socket dstSocket) {
		super(srcSocket, dstSocket);
	}
	
	/*******************
	 * Return data untouched.
	 * 
	 * @param data The data received from the source socket.
	 * @return The data to write to the destination socket.
	 ******************/
	public ByteArrayOutputStream handleData(ByteArrayOutputStream data) {
		//Return the original data untouched
		return data;
	}
}
