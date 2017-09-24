package nb.barmie.net;

import nb.barmie.exceptions.BaRMIeInvalidPortException;

/***********************************************************
 * Holder for host and port properties of a TCP endpoint.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class TCPEndpoint {
	/*******************
	 * Properties
	 ******************/
	private final String _host;
	private final int _port;
	
	/*******************
	 * Construct the TCP endpoint object with a given host and port.
	 * 
	 * @param host The host/IP to use.
	 * @param port The port to use.
	 * @throws nb.barmie.exceptions.BaRMIeInvalidPortException If the given port number is not a valid TCP port number.
	 ******************/
	public TCPEndpoint(String host, int port) throws BaRMIeInvalidPortException {
		//Store the properties
		this._host = host;
		this._port = port;
		
		//Validate the port number
		if(this._port < 1 || this._port > 65535) {
			throw new BaRMIeInvalidPortException(this._port);
		}
	}
	
	/*******************
	 * Return a string representation of this endpoint.
	 * 
	 * @return A host:port string.
	 ******************/
	public String toString() {
		return this._host + ":" + this._port;
	}
	
	/*******************
	 * Getters
	 ******************/
	public String getHost() { return this._host; }
	public int getPort() { return this._port; }
}
