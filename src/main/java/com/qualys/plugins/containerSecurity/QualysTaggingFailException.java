package com.qualys.plugins.containerSecurity;

public class QualysTaggingFailException extends Exception{
	private static final long serialVersionUID = 1L;
	
	public QualysTaggingFailException(String message){
		super(message);
	}
	
}