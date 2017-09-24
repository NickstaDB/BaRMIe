package nb.barmie.net.proxy;

import java.net.InetAddress;
import java.net.Socket;
import nb.barmie.net.proxy.thread.PassThroughProxyThread;
import nb.barmie.net.proxy.thread.UIDFixingProxyThread;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * TCP proxy server used to modify the serialVersionUID of
 * classes returned by an RMI registry so that they match
 * those of corresponding local classes.
 * 
 * This is used to enable support for additional versions
 * of RMI software without having to re-build BaRMIe to
 * use the appropriate serialVersionUID value(s).
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RMIObjectUIDFixingProxy extends ProxyServer {
	/*******************
	 * Construct the proxy.
	 * 
	 * @param targetHost The host to forward connections to.
	 * @param targetPort The port to forward connections to.
	 * @param options The program options.
	 ******************/
	public RMIObjectUIDFixingProxy(InetAddress targetHost, int targetPort, ProgramOptions options) {
		//Initialise super class
		super(targetHost, targetPort, options);
	}
	
	/*******************
	 * Create a proxy session object which allows outbound requests to pass
	 * through, but modifies the serialVersionUID values found within inbound
	 * object references.
	 * 
	 * @param clientSock A Socket for the incoming client connection.
	 * @param targetSock A Socket connected to the proxy target.
	 * @return A ProxySession object to handle the connection and data transfer.
	 ******************/
	protected ProxySession createProxySession(Socket clientSock, Socket targetSock) {
		return new ProxySession(
				new PassThroughProxyThread(clientSock, targetSock),
				new UIDFixingProxyThread(targetSock, clientSock)
		);
	}
}
