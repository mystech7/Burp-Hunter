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

import java.awt.Component;
import javax.swing.SwingUtilities;
import java.io.IOException;
import java.net.URL;
import javax.swing.JTable;

/**
 *
 * @author Jason Calvert
 */
public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IHttpListener {//IProxyListener
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HunterConfig hunterConfig;
    private HunterRequest hunterReq;
    private JTable probes; 

    @Override
    public void registerExtenderCallbacks (final IBurpExtenderCallbacks callbacks) {
        
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName ("Burp Hunter");
        
        String loaded = "Burp Hunter by Jason Calvert\n================================\n"+
                "This extension will perform injections for all \"in scope\" HTTP request made through Burp and will record the request at the specified XSS Hunter domain.\n"+
                "Use your own XSS Hunter domain or create one at https://xsshunter.com/";
        callbacks.printOutput(loaded);
        
         // create config UI
        SwingUtilities.invokeLater(() -> {
            hunterConfig = new HunterConfig();
            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(hunterConfig);
        });

        // Create preview Tab in editor
        callbacks.registerMessageEditorTabFactory(this);

        // Perform replacement and inform XSS Hunter
        callbacks.registerHttpListener(this);
    }
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new HunterTab(controller, editable);
    }
    
    class HunterTab implements IMessageEditorTab {

        private final ITextEditor txtInput;
        private byte[] currentMessage;
        private final IMessageEditorController control;

        public HunterTab(IMessageEditorController controller, boolean editable) {
            control = controller;
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(false);
        }
        
        @Override
        public String getTabCaption() {
            return "XSS Hunter Preview";
        }

        @Override
        public Component getUiComponent() {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            if (isRequest) {
                try {    
                    URL url = helpers.analyzeRequest(control.getHttpService(), content).getUrl();
                    if (url != null) {
                        if (callbacks.isInScope(url)) {
                            String req = new String(content);
                            if(hunterConfig != null) {
                                probes = hunterConfig.getProbeTable();
                                for(int row=0; row < probes.getRowCount(); row++) {
                                    if((boolean) probes.getValueAt(row, 0) == true) {
                                        if(probes.getValueAt(row, 1) != null && -1 != req.indexOf(probes.getValueAt(row, 1).toString())) {
                                            return true;
                                        }
                                    }
                                }    
                            }
                        }
                    }
                } catch (Exception ex) {}
                return false;
            }
            return false;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null)
            {
                // clear our display
                txtInput.setText(null);
            } else {
                currentMessage = content;
                //String req = new String(content);
                if("".equals(hunterConfig.getDomain())) {
                    content = "XSS Hunter needs a valid domain and access key set on configuration tab".getBytes();
                } else {
                    hunterReq = new HunterRequest(hunterConfig.getDomain(), hunterConfig.getKey());
                    try {
                        content = hunterReq.createReq(content, probes, helpers, callbacks, false);
                    } catch (IOException ex) {
                        callbacks.printError("Failed to create XSS Hunter probe:\n"+ex.toString());
                    }
                }
                txtInput.setText(content);
            }
        }

        @Override
        public byte[] getMessage() {
            return currentMessage;
        }

        @Override
        public boolean isModified() {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return txtInput.getSelectedText();
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(messageIsRequest) {
            byte[] req = messageInfo.getRequest();
            //String req = new String();
            if (callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl())) {
                if("".equals(hunterConfig.getDomain())) {
                    callbacks.printOutput("XSS Hunter needs a valid domain and access key set on configuration tab");
                } else {
                    probes = hunterConfig.getProbeTable();
                    try {
                        hunterReq = new HunterRequest(hunterConfig.getDomain(), hunterConfig.getKey());
                        req = hunterReq.createReq(req, probes, helpers, callbacks, true);
                    } catch (IOException ex) {
                        callbacks.printError("Failed to send XSS Hunter probe:\n"+ex.toString());
                    } 
                }
            }
            messageInfo.setRequest(req);
        }
    }
}
