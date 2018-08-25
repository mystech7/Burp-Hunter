/*
 * Copyright (C) 2017 Jason Calvert
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package burp;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.swing.JTable;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.HttpClients;

/**
 *
 * @author Jason Calvert
 */
public class HunterRequest {

    private static final String CHAR_LIST = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    private static final int RANDOM_STRING_LENGTH = 10;
    private final String hunterDomain;
    private final String hunterKey;
    private StringBuilder injectKey;
    
    public HunterRequest(String domain, String key) {
        hunterDomain = domain;
        hunterKey = key;
    }
    
    public byte[] createReq(byte[] content, JTable probes, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, boolean send) throws IOException {
        injectKey = new StringBuilder();
        for(int i=0; i<RANDOM_STRING_LENGTH; i++){
            int number = getRandomNumber();
            char ch = CHAR_LIST.charAt(number);
            injectKey.append(ch);
        }
        String request = new String(content);
        String b64 = "";
        String inject;
        Boolean pPresent = false;
        for(int row=0; row < probes.getRowCount(); row++) {
            if((boolean) probes.getValueAt(row, 0) == true) {
                if (request.contains(probes.getValueAt(row, 1).toString())) {
                    pPresent = true;
                    if(probes.getValueAt(row, 3) != null) {
                        String script = probes.getValueAt(row, 3).toString().replace("[DOMAIN]", hunterDomain+"/"+injectKey);
                        b64 = Base64.getEncoder().encodeToString(script.getBytes());
                        if (b64.contains("+")) {
                            script = probes.getValueAt(row, 3).toString().replace("[DOMAIN]", hunterDomain+"/"+injectKey+"?a");
                            b64 = Base64.getEncoder().encodeToString(script.getBytes());
                        }
                        if (b64.contains("+")) {
                            script = probes.getValueAt(row, 3).toString().replace("[DOMAIN]", hunterDomain+"/"+injectKey+"?aaa");
                            b64 = Base64.getEncoder().encodeToString(script.getBytes());
                        } // If b64 still contains +, give up
                    }
                    inject = probes.getValueAt(row, 2).toString().replace("[DOMAIN]", hunterDomain+"/"+injectKey);
                    inject = inject.replace("[BASE64]", b64);

                    request = request.replace(probes.getValueAt(row, 1).toString(), inject);
                
                    IRequestInfo rInfo = helpers.analyzeRequest(request.getBytes());
                    String body = request.substring(rInfo.getBodyOffset());
                    List headers = rInfo.getHeaders();
                    for (int x=0; x< headers.size(); x++) {
                        if (headers.get(x).toString().indexOf("Content-Length") == 1) {
                            headers.set(x, "Content-Length: "+body.length());   
                        }
                    }
                    content = helpers.buildHttpMessage(headers, body.getBytes());
                }
            }
        }
        
        if (send && pPresent) {
            try {
                String resp = notifyHunter(content);
                if (resp.contains("\"success\": false")) {
                    callbacks.printError(resp);
                } else {
                    callbacks.printOutput("Recorded Injection: "+injectKey);
                }
            } catch (Exception ex) {
                callbacks.printError("Unable to record injection on the host: api"+hunterDomain.substring(hunterDomain.indexOf(".")));
            }
        }
        return content;
    }
    
    public String notifyHunter(byte[] content) throws IOException {
        try {
            String request = new String(content);
            SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, (certificate, authType) -> true).build();
            HttpClient httpclient = HttpClients.custom().setSSLContext(sslContext).setSSLHostnameVerifier(new NoopHostnameVerifier()).build();
            HttpPost httpPost = new HttpPost("https://api"+hunterDomain.substring(hunterDomain.indexOf("."))+"/api/record_injection");
            String json = "{\"request\": \""+request.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r\n", "\\n")+"\", \"owner_correlation_key\": \""+hunterKey+"\", \"injection_key\": \""+injectKey+"\"}";
            StringEntity entity = new StringEntity(json);
            entity.setContentType("applicaiton/json");
            httpPost.setEntity(entity);
            HttpResponse response = httpclient.execute(httpPost);
            String responseString = new BasicResponseHandler().handleResponse(response);
            return responseString;
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException ex) {
            
            Logger.getLogger(HunterRequest.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "Error Notifying Probe Server!";
    }
    
    private int getRandomNumber() {
        int randomInt;
        Random randomGenerator = new Random();
        randomInt = randomGenerator.nextInt(CHAR_LIST.length());
        if (randomInt - 1 == -1) {
            return randomInt;
        } else {
            return randomInt - 1;
        }
    }
}