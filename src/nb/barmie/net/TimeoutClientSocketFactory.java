package nb.barmie.net;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.rmi.server.RMIClientSocketFactory;

/***********************************************************
 * An RMIClientSocketFactory implementation that sets a
 * timeout on blocking socket operations.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class TimeoutClientSocketFactory implements RMIClientSocketFactory {
	/*******************
	 * Properties
	 ******************/
	private final int _timeout; //The timeout in milliseconds before blocking socket operations return.
	
	/*******************
	 * Construct the socket factory with a given timeout value.
	 * 
	 * @param timeout The timeout in milliseconds before blocking socket operations should return.
	 ******************/
	public TimeoutClientSocketFactory(int timeout) {
		this._timeout = timeout;
	}
	
	/*******************
	 * Create a socket, set the timeout, and connect it to the given target.
	 * 
	 * @param host The host to connect to.
	 * @param port The port to connect to.
	 * @return A socket connected to the given target.s
	 * @throws IOException If an exception occurs whilst connecting to the target.
	 ******************/
	public Socket createSocket(String host, int port) throws IOException {
		Socket sock;
		
		//Create the socket, set the timeout, and connect to the target
		sock = new Socket();
		sock.setSoTimeout(this._timeout);
		sock.setSoLinger(false, 0);
		sock.connect(new InetSocketAddress(host, port), this._timeout);
		
		//Return the socket
		return sock;
	}
}
