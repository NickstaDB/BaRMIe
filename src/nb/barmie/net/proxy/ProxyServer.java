package nb.barmie.net.proxy;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import nb.barmie.exceptions.BaRMIeException;
import nb.barmie.exceptions.BaRMIeProxyAlreadyStartedException;
import nb.barmie.exceptions.BaRMIeProxyStartupException;
import nb.barmie.net.proxy.thread.PassThroughProxyThread;
import nb.barmie.util.ProgramOptions;

/***********************************************************
 * Base TCP proxy server class.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class ProxyServer extends Thread {
	/*******************
	 * Constants
	 ******************/
	private static final int SERVER_SOCK_TIMEOUT = 100;				//Time in milliseconds that the server socket should block waiting for incoming connections on each call to accept()
	private static final int SERVER_THREAD_JOIN_TIMEOUT = 300;		//Time in milliseconds to wait on shutdown for the server thread to terminate
	
	/*******************
	 * Properties
	 ******************/
	private volatile ServerSocket _serverSocket;				//The server socket used to accept connections to the proxy
	private final InetAddress _targetHost;						//The target host to connect proxy clients to
	private final int _targetPort;								//The target port to connect proxy clients to
	private int _listenPort;									//The port that the server socket should attempt to listen on (defaults to 0 for auto select)
	protected final ProgramOptions _options;					//The program options (including socket timeout value)
	protected volatile ArrayList<ProxySession> _proxySessions;	//A list of active proxy sessions, tracked purely so they can be shutdown
	private volatile BaRMIeException _startupException;			//Exception set if there is a problem starting the proxy server
	private volatile boolean _readyForConnections;				//Flag indicating that the proxy is ready to accept incoming connections
	private volatile boolean _shutdown;							//Flag indicating that the proxy server thread should shutdown
	private volatile boolean _forceShutdown;					//Flag indicating that a forced shutdown has been requested
	
	/*******************
	 * Construct the proxy.
	 * 
	 * @param targetHost The host to forward connections to.
	 * @param targetPort The port to forward connections to.
	 * @param options The program options.
	 ******************/
	public ProxyServer(InetAddress targetHost, int targetPort, ProgramOptions options) {
		this._serverSocket = null;
		this._targetHost = targetHost;
		this._targetPort = targetPort;
		this._listenPort = 0;
		this._options = options;
		this._proxySessions = new ArrayList<ProxySession>();
		this._startupException = null;
		this._readyForConnections = false;
		this._shutdown = false;
		this._forceShutdown = false;
	}
	
	/*******************
	 * Start the proxy server thread ready to start accepting incoming
	 * connections.
	 * 
	 * @throws BaRMIeException If the proxy is already running or an exception occurs during proxy startup.
	 ******************/
	final public void startProxy() throws BaRMIeException {
		//Bail if already started
		if(this._serverSocket != null) { throw new BaRMIeProxyAlreadyStartedException("The proxy server has already been started and must be shutdown before it can be started again."); }
		if(this._proxySessions.size() > 0) { throw new BaRMIeProxyAlreadyStartedException("There are existing proxy server sessions that must be terminated before starting the proxy again."); }
		
		//Reset flags and startup exception field
		this._startupException = null;
		this._readyForConnections = false;
		this._shutdown = false;
		
		//Start the proxy server thread
		this.start();
		
		//Block until the proxy is ready or an exception is thrown
		while(this._readyForConnections == false && this._startupException == null) {}
		if(this._startupException != null) {
			//Exception thrown during startup, throw it back to the caller
			throw this._startupException;
		}
	}
	
	/*******************
	 * Main thread function - creates the server socket and handles connections
	 * until the proxy is shutdown.
	 ******************/
	final public void run() {
		ProxySession ps;
		Socket clientSock;
		Socket targetSock;
		
		//Bail if already started
		if(this._serverSocket != null) { this._startupException = new BaRMIeProxyAlreadyStartedException("The proxy server has already been started and must be shutdown before it can be started again."); return; }
		if(this._proxySessions.size() > 0) { this._startupException = new BaRMIeProxyAlreadyStartedException("There are existing proxy server sessions that must be terminated before starting the proxy again."); return; }
		
		//Create the server socket
		try {
			this._serverSocket = new ServerSocket(this._listenPort, 2, InetAddress.getLoopbackAddress());
			this._serverSocket.setSoTimeout(ProxyServer.SERVER_SOCK_TIMEOUT); //Low timeout allows the server to be shutdown quicker
		} catch(Exception ex) {
			//Close the server socket if it was created
			if(this._serverSocket != null) {
				try { this._serverSocket.close(); } catch(Exception ex1) {}
				this._serverSocket = null;
			}
			
			//Store the exception and exit the thread
			this._startupException = new BaRMIeProxyStartupException("An exception occurred whilst attempting to start an RMI object proxy.", ex);
			return;
		}
		
		//Set the flag indicating that the proxy is ready to accept connections
		this._readyForConnections = true;
		
		//Enter the main proxy server loop
		while(this._shutdown == false) {
			try {
				//Attempt to accept a connection to the server socket
				clientSock = this._serverSocket.accept();
				clientSock.setSoTimeout(this._options.getSocketTimeout());
				
				//Attept to establish an outbound connection to the target
				targetSock = new Socket(this._targetHost, this._targetPort);
				targetSock.setSoTimeout(this._options.getSocketTimeout());
				
				//Create a new proxy session
				ps = this.createProxySession(clientSock, targetSock);
				if(ps != null) {
					//Add to the list of proxy sessions
					this._proxySessions.add(ps);
					
					//Start the new proxy session
					ps.start();
				}
			} catch(SocketTimeoutException ste) {
				//Server socket accept timeout passed, continue
				continue;
			} catch(SocketException se) {
				//Most likely an exception caused by a connection closing down somewhere or a proxy being terminated, swallow it up
				continue;
			} catch(Exception ex) {
				//Print the exception details
				System.out.println("[-] An exception occurred in the proxy main loop (" + this.getClass().getSimpleName() + ").\n\t" + ex.toString());
				ex.printStackTrace();
			}
		}
		
		//No longer ready to accept connections
		this._readyForConnections = false;
		
		//Close and release the server socket
		if(this._serverSocket != null) {
			try { this._serverSocket.close(); } catch(Exception ex) {}
			this._serverSocket = null;
		}
	}
	
	/*******************
	 * Stop the proxy server gracefully.
	 ******************/
	final public void stopProxy() {
		this.stopProxy(false);
	}
	
	/*******************
	 * Stop the proxy server and shutdown all proxy sessions.
	 * 
	 * @param force Set to true to force the proxy to stop immediately.
	 ******************/
	final public void stopProxy(boolean force) {
		//Don't shutdown if we're already shutting down
		if(this._shutdown == false) {
			//Set the shutdown and force shutdown flags
			this._shutdown = true;
			this._forceShutdown = force;
			
			//If the shutdown is forced, close the server socket and interrupt the thread
			if(force == true) {
				//Close the server socket
				if(this._serverSocket != null) {
					try { this._serverSocket.close(); } catch(Exception ex) {}
					this._serverSocket = null;
				}
				
				//Interrupt the thread
				if(this.isAlive()) { this.interrupt(); }
			} else {
				//Attempt to join the thread
				try { this.join(ProxyServer.SERVER_THREAD_JOIN_TIMEOUT); } catch(InterruptedException ie) {}
				if(this.isAlive()) { this.interrupt(); }
				
				//Shutdown the server socket if necessary
				if(this._serverSocket != null) {
					try { this._serverSocket.close(); } catch(Exception ex) {}
					this._serverSocket = null;
				}
			}
			
			//If there are any active proxy sessions then shut them down
			for(ProxySession ps: this._proxySessions) {
				ps.shutdown(force);
			}
			this._proxySessions.clear();
		}
	}
	
	/*******************
	 * Get the listen address of the proxy server socket.
	 * 
	 * @return The listen address of the proxy server socket.
	 ******************/
	final public InetAddress getServerListenAddress() { return this._serverSocket.getInetAddress(); }
	
	/*******************
	 * Get the local port that the proxy server is listening on.
	 * 
	 * @return The local port that the proxy server is listening on.
	 ******************/
	final public int getServerListenPort() { return this._serverSocket.getLocalPort(); }
	
	/*******************
	 * Set the local port on which the proxy server should listen.
	 * 
	 * Setting this to zero (default) will lead to a free port being selected
	 * automatically.
	 * 
	 * @param port The TCP port to listen on.
	 ******************/
	final public void setServerListenPort(int port) {
		this._listenPort = port;
	}
	
	/*******************
	 * Create a proxy session object - called when a client connects to the
	 * proxy server socket and a connection to the target has been established
	 * in order to create a ProxySession to handle transmission of data between
	 * the client and target.
	 * 
	 * By default this returns a proxy session that passes data straight through
	 * from client to server and back. This method must be overridden by
	 * sub classes in order to capture and/or manipulate data passing over the
	 * network.
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
