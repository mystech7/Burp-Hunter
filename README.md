# Burp Hunter
This is a XSS Hunter client plugin for Burp to assist in blind XSS testing. It will perform injection replacements and record the requests at the specified XSS Hunter domain for correlation if the injection executes.

## Requirements
* A XSS hunter domain, either your own or one registered at https://xsshunter.com
* XSS Hunter Correlation Key

## Setup
* Set the **Java Enviroment** location in **Burp Extender Options** tab to the lib directory containing the dependencies or place the jar files in an existing dependency folder
* Add the **BurpHunter.jar** to the list of Burp Extensions
* Click the Burp Hunter tab and set your **domain** and **correlation key**
* Add your super 1337 XSS exploit probes
* Add your target to scope
* -= Hack the Planet =-
