package nb.barmie.net.proxy;

import java.net.InetAddress;
import java.net.Socket;
import nb.barmie.net.proxy.thread.PassThroughProxyThread;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * A TCP Proxy instance which uses two pass through proxy
 * threads in order to support port forwarding.
 * 
 * In some cases RMI server applications bind objects to
 * localhost or 127.0.0.1. When an RMI client attempts to
 * use one of these objects, it attempts to connect to it
 * on the local host, rather than the remote server. This
 * proxy instance is intended to be used to forward the
 * local port to the remote server so that we can still
 * attack these endpoints.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class PortForwarder extends ProxyServer {
	/*******************
	 * Construct the port forwarder.
	 * 
	 * @param targetHost The host to forward connections to.
	 * @param targetPort The port to forward connections to.
	 * @param options The program options.
	 ******************/
	public PortForwarder(InetAddress targetHost, int targetPort, ProgramOptions options) {
		//Initialise super class
		super(targetHost, targetPort, options);
		
		//Set the listen port to the target port
		this.setServerListenPort(targetPort);
	}
	
	/*******************
	 * Create a proxy session object which allows data to pass through
	 * untouched in both directions.
	 * 
	 * @param clientSock A Socket for the incoming client connection.
	 * @param targetSock A Socket connected to the proxy target.
	 * @return A ProxySession object to handle the connection and data transfer.
	 ******************/
	protected ProxySession createProxySession(Socket clientSock, Socket targetSock) {
		return new ProxySession(
				new PassThroughProxyThread(clientSock, targetSock),
				new PassThroughProxyThread(targetSock, clientSock)
		);
	}
}
