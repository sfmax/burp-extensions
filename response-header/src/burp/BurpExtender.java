package burp;

import java.util.List;
import java.util.ListIterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IHttpListener {

	IExtensionHelpers helpers = null;
	
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// TODO Auto-generated method stub
		
		callbacks.setExtensionName("CSP Response Header Insert");
		
		this.helpers = callbacks.getHelpers();
		
		callbacks.registerHttpListener(this);	
	}
	
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		
		//Process only response
		if (messageIsRequest == false) {
			
			//Sample policy
			String cspHeader = "content-security-policy: default-src 'self'; img-src 'self' data:; script-src 'self'; Style-src 'self' 'unsafe-inline';";
			
			
			byte[] _response = messageInfo.getResponse();
			
			if(_response == null) {
				return;
			}
			
			IResponseInfo response = this.helpers.analyzeResponse(_response);
			
			//Retrieve existing headers
			List<String> responseHeaders = response.getHeaders();
			
			ListIterator<String> itr = responseHeaders.listIterator();
			
			//Check if there is already a CSP header set in the response
			String cspPattern = "Content-Security-policy:";
			Pattern pattern = Pattern.compile(cspPattern, Pattern.CASE_INSENSITIVE);
			
			Boolean foundCsp = false;
			
			while(itr.hasNext()) {
				String header = itr.next();
			    
				Matcher m = pattern.matcher(header);

				if (m.find()) {
					foundCsp = true;
				}
			}
			
			if (!foundCsp) {
				
				//CSP header is not yet present, add it to the response
				responseHeaders.add(cspHeader);
			
				//Process body - only needed to put the complete response back together
				String responseString = helpers.bytesToString(_response);
				String responseBody = responseString.substring(response.getBodyOffset()); 
				byte[] _body = helpers.stringToBytes(responseBody);
					
				byte[] httpResponse = helpers.buildHttpMessage(responseHeaders, _body);
			
				messageInfo.setResponse(httpResponse);
			}
		}
		
	}

}
