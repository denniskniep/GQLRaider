package extension;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.ITextEditor;
import extension.gql.GqlEditor;
import extension.gql.GqlInjectionPoint;
import extension.gql.GqlQueryParser;
import extension.gql.GqlRequest;
import extension.gql.GqlRequestParser;
import extension.utils.ArrayUtils;
import extension.utils.Logger;
import java.awt.Component;
import java.util.List;
import javax.swing.JTabbedPane;

public class MessageEditorTab implements IMessageEditorTab {

  private static Logger logger = BurpExtender.getLogger();
  private final IExtensionHelpers helpers;
  private BurpRequest burpRequest;
  private boolean editable;

  private final JTabbedPane tabPanel;
  private ITextEditor txtVariables;
  private ITextEditor txtQuery;
  private ITextEditor txtInjectionPoints;
  private GqlRequest gqlRequest;

  public MessageEditorTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks)  {
    this.editable = editable;
    this.helpers = callbacks.getHelpers();

    this.tabPanel = new JTabbedPane();

    this.txtQuery = callbacks.createTextEditor();
    this.txtQuery.setEditable(editable);
    this.tabPanel.addTab("Query", txtQuery.getComponent());

    this.txtVariables = callbacks.createTextEditor();
    this.txtVariables.setEditable(editable);
    this.tabPanel.addTab("Variables", txtVariables.getComponent());

    this.txtInjectionPoints = callbacks.createTextEditor();
    this.txtInjectionPoints.setEditable(false);
    this.tabPanel.addTab("Injection Points", txtInjectionPoints.getComponent());
  }

  public String getTabCaption()
  {
    return "GraphQL";
  }

  public Component getUiComponent()
  {
    return tabPanel;
  }

  public boolean isEnabled(byte[] content, boolean isRequest)
  {
    if(isRequest){
      String contentAsString = helpers.bytesToString(content);
      return contentAsString.contains("\"query\"");
    }
    return false;
  }

  public void setMessage(byte[] content, boolean isRequest)
  {
    burpRequest = BurpRequest.from(content, helpers);

    try{
      GqlRequestParser gqlRequestParser = new GqlRequestParser();
      gqlRequest = gqlRequestParser.parse(burpRequest.getBodyAsString());

      if(gqlRequest.getQuery() != null){
        txtQuery.setText(helpers.stringToBytes(gqlRequest.getQuery()));
        txtQuery.setEditable(editable);
      }else {
        clearTextField(txtQuery, editable);
      }

      if(gqlRequest.getVariables() != null){
        txtVariables.setText(helpers.stringToBytes(gqlRequest.getVariables()));
        txtVariables.setEditable(editable);
      }else {
        clearTextField(txtVariables, editable);
      }

      String injectionPoints = getInjectionPointsAsString(gqlRequest);
      txtInjectionPoints.setText(helpers.stringToBytes(injectionPoints));

    }catch (Exception e){
      clearTextField(txtQuery);
      clearTextField(txtVariables);
      clearTextField(txtInjectionPoints);
      throw e;
    }
  }

  private String getInjectionPointsAsString(GqlRequest gqlRequests) {
      GqlQueryParser parser = new GqlQueryParser();
      List<GqlInjectionPoint> injectionPoints = parser.extractInsertationPoints(gqlRequests);
      StringBuilder builder = new StringBuilder();
      for (GqlInjectionPoint injectionPoint : injectionPoints) {
        builder.append(injectionPoint.getName());
        builder.append(":");
        builder.append(injectionPoint.getValue());
        builder.append(" (");
        builder.append("Line:");
        builder.append(injectionPoint.getLine());
        builder.append(";");
        builder.append("Column:");
        builder.append(injectionPoint.getColumn());
        builder.append(")");
        builder.append("\n");
      }
      return builder.toString();
  }

  private void clearTextField(ITextEditor textEditor) {
    clearTextField(textEditor, false);
  }

  private void clearTextField(ITextEditor textEditor, boolean editable) {
    textEditor.setText(null);
    textEditor.setEditable(editable);
  }

  @Override
  public byte[] getMessage() {
    if (isModified()) {
      GqlRequest modified = new GqlRequest();

      if(txtQuery.isTextModified() ){
        modified.setQuery(helpers.bytesToString(txtQuery.getText()));
      }

      if(txtVariables.isTextModified() ){
        modified.setVariables(helpers.bytesToString(txtVariables.getText()));
      }

      GqlEditor editor = new GqlEditor();
      String modifiedJsonRequest = editor.modify(gqlRequest, modified);
      byte[] modifiedMessageBody = helpers.stringToBytes(modifiedJsonRequest);
      return ArrayUtils.concat(burpRequest.getHeader(), modifiedMessageBody);
    }
    return burpRequest.getMessage();
  }

  @Override
  public boolean isModified() {
    return (txtQuery.isTextModified() || txtVariables.isTextModified());
  }

  public byte[] getSelectedData()
  {
    return null;
  }
}
