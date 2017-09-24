package nb.barmie.net.proxy;

import nb.barmie.net.proxy.thread.ProxyThread;

/***********************************************************
 * Class representing a proxy session with a proxy thread
 * to handle data going from client to target and a proxy
 * thread to handle data going from target to client.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ProxySession {
	/*******************
	 * Properties
	 ******************/
	private final ProxyThread _outboundProxyThread;	//Proxy thread to handle data going from client to target
	private final ProxyThread _inboundProxyThread;	//Proxy thread to handle data going from target to client
	
	/*******************
	 * Construct the proxy session with the given outbound and inbound proxy
	 * threads.
	 * 
	 * @param outThread A ProxyThread instance to handle data from the client to the target.
	 * @param inThread A ProxyThread instance to handle data from the target to the client.
	 ******************/
	public ProxySession(ProxyThread outThread, ProxyThread inThread) {
		this._outboundProxyThread = outThread;
		this._inboundProxyThread = inThread;
	}
	
	/*******************
	 * Start the outbound and inbound proxy threads.
	 ******************/
	public void start() {
		this._outboundProxyThread.start();
		this._inboundProxyThread.start();
	}
	
	/*******************
	 * Shutdown the proxy session gracefully.
	 ******************/
	public void shutdown() {
		this.shutdown(false);
	}
	
	/*******************
	 * Shutdown the outbound and inbound proxy threads.
	 * 
	 * @param force Set to true to force immediate shutdown.
	 ******************/
	public void	shutdown(boolean force) {
		this._outboundProxyThread.shutdown(force);
		this._inboundProxyThread.shutdown(force);
	}
	
	/*******************
	 * Get the outbound proxy thread.
	 * 
	 * @return The outbound proxy thread.
	 ******************/
	public ProxyThread getOutboundProxyThread() {
		return this._outboundProxyThread;
	}
	
	/*******************
	 * Get the inbound proxy thread.
	 * 
	 * @return The inbound proxy thread.
	 ******************/
	public ProxyThread getInboundProxyThread() {
		return this._inboundProxyThread;
	}
}
