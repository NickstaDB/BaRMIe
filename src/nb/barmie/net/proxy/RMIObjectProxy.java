package nb.barmie.net.proxy;

import nb.barmie.net.proxy.thread.PassThroughProxyThread;
import nb.barmie.net.proxy.thread.ObjectRedirectProxyThread;
import java.net.InetAddress;
import java.net.Socket;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * TCP proxy server class which proxies an RMI registry
 * connection in order to alter remote object references
 * to point at another proxy server which proxies remote
 * method invocations.
 * 
 * This class is used to support injection of
 * deserialization payloads at the network level.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RMIObjectProxy extends ProxyServer {
	/*******************
	 * Properties
	 ******************/
	private final byte[] _payload;	//The raw bytes of the deserialization payload to use
	private final byte[] _marker;	//The raw bytes of the marker which is to be replaced with the payload in outbound method invocations
	
	/*******************
	 * Construct the proxy.
	 * 
	 * @param targetHost The host to forward connections to.
	 * @param targetPort The port to forward connections to.
	 * @param options The program options.
	 * @param payload The raw bytes of the deserialization payload that will be injected into proxied method calls.
	 * @param marker The raw bytes of a marker object that will be replaced with the payload in proxied method calls.
	 ******************/
	public RMIObjectProxy(InetAddress targetHost, int targetPort, ProgramOptions options, byte[] payload, byte[] marker) {
		//Initialise super class
		super(targetHost, targetPort, options);
		
		//Store the payload and marker bytes
		this._payload = payload;
		this._marker = marker;
	}
	
	/*******************
	 * Create a proxy session object that redirects returned remote object
	 * references through an RMIMethodCallProxy.
	 * 
	 * @param clientSock A Socket for the incoming client connection.
	 * @param targetSock A Socket connected to the proxy target.
	 * @return A ProxySession object to handle the connection and data transfer.
	 ******************/
	protected ProxySession createProxySession(Socket clientSock, Socket targetSock) {
		return new ProxySession(
				new PassThroughProxyThread(clientSock, targetSock),
				new ObjectRedirectProxyThread(targetSock, clientSock, this._options, this._payload, this._marker)
		);
	}
}
