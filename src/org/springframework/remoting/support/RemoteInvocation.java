package org.springframework.remoting.support;

import java.io.Serializable;
import java.util.Map;

/***********************************************************
 * RemoteInvocation class for Spring Framework attacks.
 * 
 * Written by Nicky Bloor (@NickstaDB).
 **********************************************************/
public class RemoteInvocation implements Serializable {
	//Dummy serialVersionUID
	private static final long serialVersionUID = 6876024250231820554L;
	
	/*******************
	 * Properties
	 ******************/
	public String methodName;
	public Class[] parameterTypes;
	public Object[] arguments;
	public Map<String, Serializable> attributes;
}
