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

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener, IExtensionStateListener {
	
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private PrintWriter stdout;
    private PrintWriter stderr;	
    
    private IContextMenuInvocation currentInvocation;
    
    private HashMap<String,IHttpRequestResponse> processedRequestResponse;
    
    private IBurpCollaboratorClientContext collaboratorContext;
    
    private InteractionServer interactionServer;

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
        
        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true); 
        
        stdout.println("Welcome to Handy Collaborator, the plugin that make it possible to use the Collaborator during manual testing!");
        stdout.println("Created by Federico Dotta and Gianluca Baldi");
        stdout.println("");
        stdout.println("Github: https://github.com/federicodotta/HandyCollaborator");
        stdout.println("");	
                
        collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        
        processedRequestResponse = new HashMap<String,IHttpRequestResponse>();
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
			
			menu.add(itemInsertCollaboratorPayload);
			
			return menu;			
			
		} else {
				
			return null;
			
		}
	}

	public void actionPerformed(ActionEvent event) {

		String command = event.getActionCommand();
	
		if(command.equals("contextInsertCollaboratorPayload")) {
			
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
		
			String currentCollaboratorPayload = collaboratorContext.generatePayload(true);
			//stdout.println(currentCollaboratorPayload);
			
			byte[] newRequestResponseBytes = ArrayUtils.addAll(preSelectedPortion, helpers.stringToBytes(currentCollaboratorPayload));
			newRequestResponseBytes = ArrayUtils.addAll(newRequestResponseBytes, postSelectedPortion);
			
			if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
				selectedItems[0].setRequest(newRequestResponseBytes);
			} else {
				selectedItems[0].setResponse(newRequestResponseBytes);
			}
			
			// Add request/response to processed requests/responses
			processedRequestResponse.put(currentCollaboratorPayload, selectedItems[0]);

		}
		
	}

	public void extensionUnloaded() {

		stdout.println("Stopping thread of Collaborator interaction server");
		interactionServer.setGoOn(false);
		
	}

}
