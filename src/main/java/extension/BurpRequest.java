package extension;

import burp.IExtensionHelpers;
import burp.IRequestInfo;
import java.util.Arrays;

public class BurpRequest {

  private IRequestInfo requestInfo;
  private byte[] message;
  private byte[] header;
  private byte[] body;
  private String headerAsString;
  private String bodyAsString;

  private BurpRequest(byte[] message, IRequestInfo requestInfo, byte[] header, byte[] body, String headerAsString,
      String bodyAsString) {
    this.message = message;
    this.requestInfo = requestInfo;
    this.header = header;
    this.body = body;
    this.headerAsString = headerAsString;
    this.bodyAsString = bodyAsString;
  }

  public static BurpRequest from(byte[] message, IExtensionHelpers helpers){
    IRequestInfo requestInfo = helpers.analyzeRequest(message);
    byte[] header = Arrays.copyOfRange(message, 0, requestInfo.getBodyOffset());
    byte[] body = Arrays.copyOfRange(message, requestInfo.getBodyOffset(), message.length);

    String headerAsString = helpers.bytesToString(header);
    String bodyAsString = helpers.bytesToString(body);

    return new BurpRequest(message, requestInfo, header, body, headerAsString, bodyAsString);
  }

  public IRequestInfo getRequestInfo() {
    return requestInfo;
  }

  public byte[] getMessage() {
    return message;
  }

  public byte[] getHeader() {
    return header;
  }

  public byte[] getBody() {
    return body;
  }

  public String getHeaderAsString() {
    return headerAsString;
  }

  public String getBodyAsString() {
    return bodyAsString;
  }
}
