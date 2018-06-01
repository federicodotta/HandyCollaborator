# Handy Collaborator
Handy Collaborator is a Burp Suite Extension that lets you use the Collaborator tool during manual testing in a comfortable way. It is possible to generate a Collaborator payload from the contextual menu of editable tabs (Repeater, Intercept, etc.) and a separate thread will check periodically all interactions (DNS, HTTP and SMTP) received by the Collaborator for the generated payloads. If an interaction is found, an issue with all the details is added to the target host.

# Authors
- Federico Dotta, Security Advisor at @ Mediaservice.net
- Gianluca Baldi, Security Expert at @ Mediaservice.net

# Installation
1.	Download Burp Suite: http://portswigger.net/burp/download.html
2.	Install Handy Collaborator from the BApp Store or follow these steps:
3.	Download the last release of Handy Collaborator
4.	Open Burp -> Extender -> Extensions -> Add -> Choose HandyCollaboratorXX.jar file

# Usage and examples
1.	In the Repeater or the Intercept tab, right click on the point where you want to insert the Collaborator payload (or select a portion of text that will be replaced with the Collaborator payload) and click on "Insert Collaborator payload" or on "Insert Collaborator insertion point". 
2.	Execute the request with the payload or with the insertion point
3.	If the payload causes an external interaction (DNS, HTTP or SMTP), soon an issue will appear in the Target tab with all the details of the interaction (request/reponse, type, timestamp and specific details that depend on the type of interaction)
4.	That's all!

If you choose the "Insert Collaborator insertion point" option, the insertion point will be transparently replaced with a new Collaborator payload every time that the request will be executed. In this way, if you execute multiple tests on the same request, a different Collaborator URL will be transparently inserted in each request and, in the case of an interaction, the exact request responsible for the interaction will be reported. 

# Limitations
Currently, due to limitations in Burp Suite API, it is not possible to retrieve details on Collaborator interactions related to the payloads generated with this extension after unloading the extension or closing Burp Suite. The reason is that it is not possible to save the Collaborator context. An issue has been opened in Burp Suite Support Center on February 2017 and maybe this feature will be added in future (fingers crossed).

# Screenshot
![Handy Collaborator Screenshot](https://raw.githubusercontent.com/federicodotta/HandyCollaborator/master/HandyCollaborator1.png)
![Handy Collaborator Screenshot](https://raw.githubusercontent.com/federicodotta/HandyCollaborator/master/HandyCollaborator2.png)
![Handy Collaborator Screenshot](https://raw.githubusercontent.com/federicodotta/HandyCollaborator/master/HandyCollaborator4.png)
![Handy Collaborator Screenshot](https://raw.githubusercontent.com/federicodotta/HandyCollaborator/master/HandyCollaborator3.png)

# MIT License

Copyright (c) 2017 Handy Collaborator  

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:  

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.  

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.