package nb.barmie.net.proxy.thread;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/***********************************************************
 * Abstract base class representing a proxy thread that
 * reads from one socket and writes to another.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public abstract class ProxyThread extends Thread {
	/*******************
	 * Constants
	 ******************/
	private static final int PROXY_THREAD_JOIN_TIMEOUT = 5300;		//Time in milliseconds to wait on shutdown for the server thread to terminate
	
	/*******************
	 * Properties
	 ******************/
	protected volatile Socket _sourceSocket;	//The source socket to read data from
	protected volatile Socket _destSocket;		//The destination socket to write data to
	protected volatile boolean _shutdown;		//Flag indicating that the proxy thread should shutdown
	
	/*******************
	 * Construct the proxy thread with a given source and destination socket.
	 * 
	 * @param srcSocket The source socket to read data from.
	 * @param dstSocket The destination socket to write data to.
	 ******************/
	public ProxyThread(Socket srcSocket, Socket dstSocket) {
		this._sourceSocket = srcSocket;
		this._destSocket = dstSocket;
		this._shutdown = false;
	}
	
	/*******************
	 * The proxy thread function which reads from the source socket, passes the
	 * data off to be handled, then writes the result to the destination socket.
	 ******************/
	public void run() {
		InputStream inStream;
		OutputStream outStream;
		ByteArrayOutputStream byteStream;
		byte[] readBuffer;
		int readLength;
		
		//Create the byte stream and read buffer
		byteStream = new ByteArrayOutputStream(8192);
		readBuffer = new byte[8192];
		
		//Start the main loop transferring data from the source to the destination
		try {
			//Get the input/output streams from the sockets
			inStream = this._sourceSocket.getInputStream();
			outStream = this._destSocket.getOutputStream();
			
			//Loop until shutdown
			while(this._shutdown == false) {
				//Read from the source socket
				readLength = inStream.read(readBuffer, 0, 8192);
				if(readLength == -1) {
					//Connection closed, break out of the loop
					break;
				}
				
				//Reset the byte stream and put the received data into it
				byteStream.reset();
				byteStream.write(readBuffer, 0, readLength);
				
				//Pass the data on to be handled and write the result to the output stream
				outStream.write(this.handleData(byteStream).toByteArray());
			}
		} catch(IOException ex) {
			//Exception occurred, print exception details if it wasn't a closed socket or connection reset
			if(ex.getMessage().equals("Socket Closed") == false && ex.getMessage().equals("Connection reset") == false && ex.getMessage().equals("Read timed out") == false) {
				//Print the exception
				System.out.println("[-] An exception occurred during the " + this.getClass().getSimpleName() + " main loop.\n\t" + ex.toString());
			}
			
			//Sleep briefly in case the thread is already shutting down
			try { Thread.sleep(100); } catch(InterruptedException ie) { return; }
			
			//Shutdown the proxy thread if it isn't already shutting down
			if(this._shutdown == false) {
				this.shutdown();
			}
		}
	}
	
	/*******************
	 * Shutdown the proxy thread gracefully.
	 ******************/
	public final void shutdown() {
		this.shutdown(false);
	}
	
	/*******************
	 * Shutdown the proxy thread.
	 * 
	 * @param force Set to true to force immediate shutdown.
	 ******************/
	public final void shutdown(boolean force) {
		//Shutdown could be called from run() so do nothing if the shutdown flag is already set
		if(this._shutdown == false) {
			//Set the shutdown flag
			this._shutdown = true;
			
			//If the shutdown is forced, close the sockets and interrupt the thread
			if(force == true) {
				//Close the sockets
				if(this._sourceSocket != null) {
					try { this._sourceSocket.close(); } catch(Exception ex) {}
					this._sourceSocket = null;
				}
				if(this._destSocket != null) {
					try { this._destSocket.close(); } catch(Exception ex) {}
					this._destSocket = null;
				}
				
				//Interrupt the thread
				if(this.isAlive()) { this.interrupt(); }
			} else {
				//Attempt to join the thread
				try { this.join(ProxyThread.PROXY_THREAD_JOIN_TIMEOUT); } catch(InterruptedException ie) {}
				if(this.isAlive()) { this.interrupt(); }
				
				//Close the sockets
				if(this._sourceSocket != null) {
					try { this._sourceSocket.close(); } catch(Exception ex) {}
					this._sourceSocket = null;
				}
				if(this._destSocket != null) {
					try { this._destSocket.close(); } catch(Exception ex) {}
					this._destSocket = null;
				}
			}
			
			//Call handleShutdown() so sub classes can shutdown too
			this.handleShutdown(force);
		}
	}
	
	/*******************
	 * Overridable method that will be called to allow sub classes to handle
	 * shutting down.
	 * 
	 * @param force Set to true to force immediate shutdown.
	 ******************/
	public void handleShutdown(boolean force) {
	}
	
	/*******************
	 * Handle data passing through this proxy thread.
	 * 
	 * @param data The data received from the source socket.
	 * @return The data to write to the destination socket.
	 ******************/
	public abstract ByteArrayOutputStream handleData(ByteArrayOutputStream data);
}
