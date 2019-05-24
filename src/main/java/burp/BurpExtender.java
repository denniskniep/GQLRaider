package burp;

import extension.MessageEditorTabFactory;
import extension.InsertationPointProvider;
import extension.utils.Logger;

public class BurpExtender implements IBurpExtender
{

  public static final String EXTENSION_NAME = "GraphQL Raider";
  private static IBurpExtenderCallbacks callbacks;

  public static Logger getLogger(){
    return new Logger(callbacks);
  }

  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
  {
    this.callbacks = callbacks;
    getLogger().log("Started " + EXTENSION_NAME);

    // set our extension name
    callbacks.setExtensionName(EXTENSION_NAME);

    // register ourselves as a scanner insertion point provider
    callbacks.registerScannerInsertionPointProvider(new InsertationPointProvider(callbacks.getHelpers()));

    // register ourselves as a message editor tab factory
    callbacks.registerMessageEditorTabFactory(new MessageEditorTabFactory(callbacks));
  }
}