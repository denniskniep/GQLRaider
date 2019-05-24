package extension.utils;

import burp.IBurpExtenderCallbacks;

public class Logger {

  private IBurpExtenderCallbacks callbacks;

  public Logger(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
  }

  public void log(String message){
    if(callbacks!= null){
      callbacks.printOutput(message);
    }
  }
}
