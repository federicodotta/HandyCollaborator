package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import javax.swing.JMenuItem;

import org.apache.commons.lang3.ArrayUtils;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener, IExtensionStateListener, IHttpListener {
	
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private PrintWriter stdout;
    private PrintWriter stderr;	
    
    private IContextMenuInvocation currentInvocation;
    
    private HashMap<String,IHttpRequestResponsePersisted> processedRequestResponse;
    
    private IBurpCollaboratorClientContext collaboratorContext;
    
    private InteractionServer interactionServer;
    
    private final String collaboratorInsertionPointString = (char)167 + "COLLABORATOR_PAYLOAD" + (char)167;

	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        
        // Obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // Set our extension name
        callbacks.setExtensionName("Handy Collaborator");
        
        //register to produce options for the context menu
        callbacks.registerContextMenuFactory(this);
        
        //register to get extension state changes
        callbacks.registerExtensionStateListener(this); 
        
        // register ourselves as an HttpListener
        callbacks.registerHttpListener(this);
        
        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true); 
        
        stdout.println("Welcome to Handy Collaborator, the plugin that make it possible to use the Collaborator during manual testing!");
        stdout.println("Created by Federico Dotta and Gianluca Baldi");
        stdout.println("");
        stdout.println("Github: https://github.com/federicodotta/HandyCollaborator");
        stdout.println("");	
                
        collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        
        processedRequestResponse = new HashMap<String,IHttpRequestResponsePersisted>();
        interactionServer = new InteractionServer(callbacks,processedRequestResponse,collaboratorContext);
        
        interactionServer.start();
		
	}

	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

		if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || 
		   invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE) {
			
			currentInvocation = invocation;
			
			List<JMenuItem> menu = new ArrayList<JMenuItem>();
			
			JMenuItem itemInsertCollaboratorPayload = new JMenuItem("Insert collaborator payload");
			itemInsertCollaboratorPayload.setActionCommand("contextInsertCollaboratorPayload");
			itemInsertCollaboratorPayload.addActionListener(this);	
			
			JMenuItem itemInsertCollaboratorInsertionPoint = new JMenuItem("Insert collaborator insertion point");
			itemInsertCollaboratorInsertionPoint.setActionCommand("contextInsertCollaboratorInsertionPoint");
			itemInsertCollaboratorInsertionPoint.addActionListener(this);	
			
			menu.add(itemInsertCollaboratorPayload);
			menu.add(itemInsertCollaboratorInsertionPoint);
			
			return menu;			
			
		} else {
				
			return null;
			
		}
	}

	public void actionPerformed(ActionEvent event) {

		String command = event.getActionCommand();
	
		if(command.equals("contextInsertCollaboratorPayload") || command.equals("contextInsertCollaboratorInsertionPoint")) {
			
			IHttpRequestResponse[] selectedItems = currentInvocation.getSelectedMessages();
			int[] selectedBounds = currentInvocation.getSelectionBounds();
			byte selectedInvocationContext = currentInvocation.getInvocationContext();
		
			byte[] selectedRequestOrResponse = null;
			if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
				selectedRequestOrResponse = selectedItems[0].getRequest();
			} else {
				selectedRequestOrResponse = selectedItems[0].getResponse();
			}
						
			// It works if something is selected and if is not
			byte[] preSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, 0, selectedBounds[0]);
			byte[] postSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[1], selectedRequestOrResponse.length);
		
			String currentCollaboratorPayload = "";
			
			if(command.equals("contextInsertCollaboratorPayload")) {			
				currentCollaboratorPayload = collaboratorContext.generatePayload(true);
			} else {
				currentCollaboratorPayload = collaboratorInsertionPointString;
			}				
			//stdout.println(currentCollaboratorPayload);
			
			byte[] newRequestResponseBytes = ArrayUtils.addAll(preSelectedPortion, helpers.stringToBytes(currentCollaboratorPayload));
			newRequestResponseBytes = ArrayUtils.addAll(newRequestResponseBytes, postSelectedPortion);
			
			if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
				selectedItems[0].setRequest(newRequestResponseBytes);
			} else {
				selectedItems[0].setResponse(newRequestResponseBytes);
			}
			
			// Add request/response to processed requests/responses
			if(command.equals("contextInsertCollaboratorPayload")) {
				processedRequestResponse.put(currentCollaboratorPayload, callbacks.saveBuffersToTempFiles(selectedItems[0]));
			}

		}
		
	}

	public void extensionUnloaded() {

		stdout.println("Stopping thread of Collaborator interaction server");
		interactionServer.setGoOn(false);
		
	}
	
	private void replaceInsertionPointWithPayload(IHttpRequestResponse messageInfo, boolean request) {
		
		String requestResponse = "";
		
		if(request){
			byte[] requestByte = messageInfo.getRequest();
			requestResponse = new String(requestByte);			
		} else {
			byte[] responseByte = messageInfo.getResponse();
			requestResponse = new String(responseByte);	
		}
		
		// Count occurences of insertion point string in request/response
		int lastIndex = 0;
		int count = 0;
		while(lastIndex != -1){

		    lastIndex = requestResponse.indexOf(collaboratorInsertionPointString,lastIndex);

		    if(lastIndex != -1){
		        count ++;
		        lastIndex += collaboratorInsertionPointString.length();
		    }
		}
		
		// Replace all the occurrences with a Collaborator payload
		String[] collaboratorPayloads = new String[count];
		for(int i=0; i<count; i++) {
			collaboratorPayloads[i] = collaboratorContext.generatePayload(true);
			requestResponse = requestResponse.replaceFirst(collaboratorInsertionPointString, collaboratorPayloads[i]);
		}
		
		// Replace request/response with new one
		if(request){
			messageInfo.setRequest(requestResponse.getBytes());
		} else {
			messageInfo.setResponse(requestResponse.getBytes());
		}
		
		// Save all requests/reponses and collaborator payloads
		for(int i=0; i<count; i++) {
			processedRequestResponse.put(collaboratorPayloads[i], callbacks.saveBuffersToTempFiles(messageInfo));
		}
		
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

		if(messageIsRequest) {
		
			byte[] requestByte = messageInfo.getRequest();
			String requestString = new String(requestByte);
			
			// Check if request contains the vector
			if(requestString.contains(collaboratorInsertionPointString)) {
				
				replaceInsertionPointWithPayload(messageInfo, true);
				
			}
				
		} else {
			
			byte[] responseByte = messageInfo.getResponse();
			String responseString = new String(responseByte);
			
			// Check if request contains the vector
			if(responseString.contains(collaboratorInsertionPointString)) {
				
				replaceInsertionPointWithPayload(messageInfo, false);			
				
			}
    		
		}
		
	}
	
}
