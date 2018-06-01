package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.json.*;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

import org.apache.commons.lang3.ArrayUtils;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener, IExtensionStateListener, IHttpListener,  ITab {
	
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private PrintWriter stdout;
    private PrintWriter stderr;	
    
    private IContextMenuInvocation currentInvocation;
    
    private HashMap<String,IHttpRequestResponsePersisted> processedRequestResponse;
    
    private IBurpCollaboratorClientContext collaboratorContext;
    
    private InteractionServer interactionServer;
    
    private final String collaboratorInsertionPointString = (char)167 + "COLLABORATOR_PAYLOAD" + (char)167;
    
    private String currentCollaboratorLocation;
    private boolean currentCollaboratorPollOverUnenecryptedHttp;
    private String currentCollaboratorPollingLocation;
    private String currentCollaboratorType;
    
    private JPanel mainPanel;
    private JCheckBox enablePolling;

	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

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
        
        stdout.println("Welcome to Handy Collaborator, the plugin that make it comfortable to use the Collaborator during manual testing!");
        stdout.println("Created by Federico Dotta and Gianluca Baldi");
        stdout.println("");
        stdout.println("Github: https://github.com/federicodotta/HandyCollaborator");
        stdout.println("");	
                
        initializeCurrentCollaboratorVariables();
        
        if(!(currentCollaboratorType.equals("none"))) {
        	collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        } else {
        	collaboratorContext = null;
        }
        
        processedRequestResponse = new HashMap<String,IHttpRequestResponsePersisted>();
        
        interactionServer = new InteractionServer(callbacks,processedRequestResponse,collaboratorContext);
                
        interactionServer.start();
        
        SwingUtilities.invokeLater(new Runnable()  {
        	
            @Override
            public void run()  {
            	
            	mainPanel = new JPanel();
            	mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
            	
            	JPanel innerPanel = new JPanel();
            	innerPanel.setLayout(new BoxLayout(innerPanel, BoxLayout.Y_AXIS));
            	innerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            	
            	JLabel pollingTitleLabel = new JLabel("Polling options");
            	pollingTitleLabel.setForeground(new Color(249,130,11));
            	pollingTitleLabel.setFont(new Font("Nimbus", Font.BOLD, 16));
            	pollingTitleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
            	
            	JLabel enablePollingLabel = new JLabel();            			
            	String enablePollingLabelContent = "Unchecking this checkbox will temporary disable polling interactions from Collaborator "
            			+ "Server. This option WILL NOT delete Collaborator Contexts. If you re-enable the flag you will get all the interactions"
            			+ " of the current contexts, included the ones generated when polling was disabled. This option is usefull during internal"
            			+ " penetration tests in order to avoid lot of polling alerts in \"Alert\" in Burp Suite Alertts tab. After the internal"
            			+ " penetration test you can connect to Internet and obtain all the interactions of the internal penetration test. "
            			+ "Remeber that if you close Burp Suite you will loose all Collaborato Interactions (by Burp Suite design)";
            	enablePollingLabel.setText("<html>" + enablePollingLabelContent + "</html>");
            	enablePollingLabel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
            	
            	enablePolling = new JCheckBox("Enable polling");
            	enablePolling.setSelected(true);
            	enablePolling.setActionCommand("enableDisablePolling");
            	enablePolling.addActionListener(BurpExtender.this);
            	enablePolling.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
            	
            	innerPanel.add(pollingTitleLabel);
            	innerPanel.add(enablePollingLabel);
            	innerPanel.add(enablePolling);
            	
            	mainPanel.add(innerPanel);
            	
            	callbacks.customizeUiComponent(mainPanel);
                
                callbacks.addSuiteTab(BurpExtender.this);
            	
            }
            
        });
		
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
		
	public void initializeCurrentCollaboratorVariables() {
		
		String collaboratorOption = callbacks.saveConfigAsJson("project_options.misc.collaborator_server");
		JSONObject rootJsonObject = new JSONObject(collaboratorOption);
		currentCollaboratorLocation = rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("location");
		currentCollaboratorPollOverUnenecryptedHttp = rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getBoolean("poll_over_unencrypted_http");
		currentCollaboratorPollingLocation = rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("polling_location");
		currentCollaboratorType = rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("type");
		
	}
	
	public boolean isCollaboratorChanged() {		
		
		String collaboratorOption = callbacks.saveConfigAsJson("project_options.misc.collaborator_server");
		JSONObject rootJsonObject = new JSONObject(collaboratorOption);
				
		if(!(currentCollaboratorLocation.equals(rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("location"))) ||
		   !(currentCollaboratorPollOverUnenecryptedHttp == rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getBoolean("poll_over_unencrypted_http")) ||
		   !(currentCollaboratorPollingLocation.equals(rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("polling_location"))) ||
		   !(currentCollaboratorType.equals(rootJsonObject.getJSONObject("project_options").getJSONObject("misc").getJSONObject("collaborator_server").getString("type"))) ) {
			return true;
		} else {
			return false;
		}
		
	}
	
	public void checkCollaboratorChanges() {
		
		if(isCollaboratorChanged()) {
			
			initializeCurrentCollaboratorVariables();
			
			if(!(currentCollaboratorType.equals("none"))) {
				
				stdout.println("Collaborator location changed! Adding a new collaborator context to the polling thread!");
				collaboratorContext = callbacks.createBurpCollaboratorClientContext();
				interactionServer.addNewCollaboratorContext(collaboratorContext);
									
			} else {
				collaboratorContext = null;
				stdout.println("Collaborator disabled!");

			}		
			
		}
		
	}

	public void actionPerformed(ActionEvent event) {

		String command = event.getActionCommand();
		
		if(command.equals("enableDisablePolling")) {
			
			if(enablePolling.isSelected()) {
				
				interactionServer.resumeThread();
				
			} else {
				
				interactionServer.pause();
				
			}
	
		} else if(command.equals("contextInsertCollaboratorPayload") || command.equals("contextInsertCollaboratorInsertionPoint")) {
			
			// DEBUG
			//String collaboratorOption = callbacks.saveConfigAsJson("project_options.misc.collaborator_server");
			//stdout.println(collaboratorOption);
			
			checkCollaboratorChanges();			
			
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
			
			if(collaboratorContext == null) {
				currentCollaboratorPayload = "THE_COLLABORATOR_IS_DISABLED";
			} else if(command.equals("contextInsertCollaboratorPayload")) {			
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
		
		checkCollaboratorChanges();
		
		if(collaboratorContext != null) {
		
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
			
		} else {
			
			stderr.println("The collaborator is disabled. Replacement with collaborator payload is not possible...");
			
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

	@Override
	public String getTabCaption() {
		return "Handy Collaborator";
	}

	@Override
	public Component getUiComponent() {
		return mainPanel;
	}
	
}
