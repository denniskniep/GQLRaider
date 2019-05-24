package extension;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class MessageEditorTabFactory implements IMessageEditorTabFactory {

  private IBurpExtenderCallbacks callbacks;

  public MessageEditorTabFactory(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
  }

  public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
    return new MessageEditorTab(controller, editable, callbacks);
  }
}
