package burp;

import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;
import java.util.Date;

//import java.util.Iterator;
//import java.util.Map;
//import java.util.Set;

public class InteractionServer extends Thread {

	private IBurpExtenderCallbacks callbacks;
	private HashMap<String,IHttpRequestResponsePersisted> processedRequestResponse;
	
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    private IBurpCollaboratorClientContext collaboratorContext;
    
    private volatile boolean goOn;
    
    private static final String issueName = " Collaborator interaction - Handy Collaborator";
    String remediation = "The remediations depends on the specific issue manually tested.";
    private static final String severity = "High";
    private static final String confidence = "Certain";
    
    private static final int pollingMilliseconds = 3000;
	
	public InteractionServer(IBurpExtenderCallbacks callbacks, HashMap<String,IHttpRequestResponsePersisted> processedRequestResponse, IBurpCollaboratorClientContext collaboratorContext) {
		
		this.callbacks = callbacks;
		this.processedRequestResponse = processedRequestResponse;
		
        // Initialize stdout and stderr
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.stderr = new PrintWriter(callbacks.getStderr(), true); 
        		
		this.collaboratorContext = collaboratorContext;
		
		this.goOn = true;
		
	}
	
	public void setGoOn(boolean goOn) {
		this.goOn = goOn;
	}
	
	public void addIssue(IBurpCollaboratorInteraction interaction) {
		
		String interactionId = interaction.getProperty("interaction_id");
		IHttpRequestResponse requestResponse = processedRequestResponse.get(interactionId + "." + collaboratorContext.getCollaboratorServerLocation());
		
		String issueDetails = "";
		
		// Convert timestamp to local time
		String dateStr = interaction.getProperty("time_stamp");
        SimpleDateFormat sdf =  new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss z");
        TimeZone tz = TimeZone.getDefault();
        sdf.setTimeZone(tz);
        String localTimestamp = "";
        try{
        	Date date = sdf.parse(dateStr);
        	localTimestamp = sdf.format(date);
        } catch(Exception e) {
        	localTimestamp = dateStr;
        }
		
		switch (interaction.getProperty("type")) {
		
			case "DNS":
				
				issueDetails = "The Collaborator server received a DNS lookup of type " + interaction.getProperty("query_type") +
							   " for the domain name " + interaction.getProperty("interaction_id") + "." + 
							   collaboratorContext.getCollaboratorServerLocation() + "<br /><br />" +
						       "The lookup was received from IP address " + interaction.getProperty("client_ip") + " at " + 
						       localTimestamp + "<br /><br />" + "DNS query (encoded in Base64)<br />" + 
						       interaction.getProperty("raw_query");
				break;
				
			case "HTTP":
				
				issueDetails = "The Collaborator server received an HTTP request for the domain name " + interaction.getProperty("interaction_id") + 
								"." + collaboratorContext.getCollaboratorServerLocation() + ".<br /><br />The request was received from IP address " + 
								interaction.getProperty("client_ip") + " at " + localTimestamp + "<br /><br />" +
								"Request to collaborator (encoded in Base64)<br />" +  interaction.getProperty("request")  + "<br /><br />" +
								"Response from collaborator (encoded in Base64)<br />" +  interaction.getProperty("response"); 
				
				break;
				
			case "SMTP":
				
				String decodedConversation = new String(Base64.getDecoder().decode(interaction.getProperty("conversation")));
				
				Pattern p = Pattern.compile(".*mail from:.*?<(.*?)>.*rcpt to:.*?<(.*?)>.*\\r\\n\\r\\n(.*?)\\r\\n\\.\\r\\n.*",Pattern.CASE_INSENSITIVE + Pattern.DOTALL);
				Matcher m = p.matcher(decodedConversation);	
				
				if(m.find()) {
					String from = m.group(1);
					String to = m.group(2);
					String message = m.group(3);
					
					issueDetails = "The Collaborator server received an SMTP connection from IP address " + 
					               interaction.getProperty("client_ip") + " at " + localTimestamp + "<br /><br />" +
					               "The email details were:<br /><br />From:<br />" + from + "<br /><br />To:<br />" + to + 
					               "<br /><br />Message:<br />" + message + "<br /><br />" +
					               "SMTP Conversation:<br /><br />" + decodedConversation.replace("\r\n", "<br />");
				} else {
					issueDetails = "The Collaborator server received an SMTP connection from IP address " + 
				               interaction.getProperty("client_ip") + " at " + localTimestamp + "<br /><br />" +
				               "SMTP Conversation:<br /><br />" + decodedConversation.replace("\r\n", "<br />");
				}
				
				break;
				
			default:
				
				issueDetails = "The Collaborator server received a " + interaction.getProperty("type") +  " interaction from IP address " + 
			               interaction.getProperty("client_ip") + " at " + localTimestamp + " (domain name: " +
			               interaction.getProperty("interaction_id") + "." + collaboratorContext.getCollaboratorServerLocation() + ")";
				
				break;
		
		}
		
		CustomScanIssue newIssue = new CustomScanIssue(
				requestResponse.getHttpService(),
                callbacks.getHelpers().analyzeRequest(requestResponse).getUrl(), 
                new IHttpRequestResponse[] { requestResponse }, 
                interaction.getProperty("type") + issueName,
                severity,
                confidence,
                issueDetails,
                remediation);

		callbacks.addScanIssue(newIssue);
	
	}
	
	public void run() {
		
		stdout.println("Thread started");
		
		while(goOn) {
			
			List<IBurpCollaboratorInteraction> allCollaboratorInteractions = collaboratorContext.fetchAllCollaboratorInteractions();
			
			for(int i=0;  i < allCollaboratorInteractions.size(); i++) {
								
				addIssue(allCollaboratorInteractions.get(i));
				
				/*
				// DEBUG - Print all interaction properties
				Map<java.lang.String,java.lang.String> currentProperties = allCollaboratorInteractions.get(i).getProperties();
				Set<String> a = currentProperties.keySet();
				Iterator<String> b = a.iterator();
				while(b.hasNext()) {
					String d = b.next();
					stdout.println(d);
					stdout.println(currentProperties.get(d));
				}
				*/
				
			}
			
			try {
				Thread.sleep(pollingMilliseconds);
			} catch (InterruptedException e) {
				stderr.println(e.toString());
			}

		}
				
	}

}
