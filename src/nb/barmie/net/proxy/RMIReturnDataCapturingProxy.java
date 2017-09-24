package nb.barmie.net.proxy;

import nb.barmie.net.proxy.thread.ReplyDataCapturingProxyThread;
import nb.barmie.net.proxy.thread.PassThroughProxyThread;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * TCP proxy used to handle connections to RMI registry
 * services and capture the contents of ReturnData packets
 * which can then be parsed to extract details of objects
 * that are exposed through the registry.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RMIReturnDataCapturingProxy extends ProxyServer {
	/*******************
	 * Properties
	 ******************/
	private volatile boolean _reconnectOccurred;	//Flag indicating whether a reconnect has occurred to the RMI proxy
	
	/*******************
	 * Construct the proxy.
	 * 
	 * @param targetHost The host to forward connections to.
	 * @param targetPort The port to forward connections to.
	 * @param options The program options.
	 ******************/
	public RMIReturnDataCapturingProxy(InetAddress targetHost, int targetPort, ProgramOptions options) {
		//Initialise super class
		super(targetHost, targetPort, options);
		
		//Clear the reconnect flag
		this._reconnectOccurred = false;
	}
	
	/*******************
	 * Create a proxy session object to capture RMI Reply Data packets coming
	 * back from the target.
	 * 
	 * Additionally - the RMI connection might timeout and reconnect in some
	 * cases, so if there's an existing proxy session then we shut it down and
	 * set a flag indicating that a reconnect has occurred so that the user of
	 * this proxy can retry the previous operation.
	 * 
	 * @param clientSock A Socket for the incoming client connection.
	 * @param targetSock A Socket connected to the proxy target.
	 * @return A ProxySession object to handle the connection and data transfer.
	 ******************/
	protected ProxySession createProxySession(Socket clientSock, Socket targetSock) {
		//If there's an active session then a reconnect occurred
		if(this._proxySessions.size() == 1) {
			//Shutdown the old session
			this._proxySessions.get(0).shutdown();
			this._proxySessions.remove(0);
			
			//Set the reconnect flag
			this._reconnectOccurred = true;
		}
		
		//Create and return a new proxy session that passes outbound data through and captures reply data
		return new ProxySession(
				new PassThroughProxyThread(clientSock, targetSock),
				new ReplyDataCapturingProxyThread(targetSock, clientSock)
		);
	}
	
	/*******************
	 * Reset the inbound data buffer on the active proxy session.
	 ******************/
	public void resetDataBuffer() {
		if(this._proxySessions.size() == 1) {
			((ReplyDataCapturingProxyThread)this._proxySessions.get(0).getInboundProxyThread()).resetDataBuffer();
		}
	}
	
	/*******************
	 * Get the inbound data buffer from the active proxy session.
	 * 
	 * @return An ArrayList of Bytes representing the buffered data, or null if there isn't an active proxy session.
	 ******************/
	public ArrayList<Byte> getDataBuffer() {
		if(this._proxySessions.size() == 1) {
			return ((ReplyDataCapturingProxyThread)this._proxySessions.get(0).getInboundProxyThread()).getDataBuffer();
		} else {
			return null;
		}
	}
	
	/*******************
	 * Check if Java reconnected to the RMI registry proxy.
	 * 
	 * @return True if a reconnect occurred.
	 ******************/
	public boolean didReconnect() {
		return this._reconnectOccurred;
	}
	
	/*******************
	 * Reset the reconnection flag.
	 ******************/
	public void resetReconnectFlag() {
		this._reconnectOccurred = false;
	}
}
