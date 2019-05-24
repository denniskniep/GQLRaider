package extension;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IScannerInsertionPoint;
import extension.gql.GqlEditor;
import extension.gql.GqlInjectionPoint;
import extension.gql.GqlRequest;
import extension.utils.ArrayUtils;
import extension.utils.Logger;

public class InsertationPoint implements IScannerInsertionPoint {

  private static Logger logger = BurpExtender.getLogger();
  private IExtensionHelpers helpers;

  private BurpRequest burpRequest;
  private GqlRequest gqlRequest;
  private GqlInjectionPoint insertationPoint;

  public InsertationPoint(IExtensionHelpers helpers, BurpRequest burpRequest, GqlRequest gqlRequest,
      GqlInjectionPoint insertationPoint) {
    this.helpers = helpers;
    this.burpRequest = burpRequest;
    this.gqlRequest = gqlRequest;
    this.insertationPoint = insertationPoint;
  }

  @Override
  public String getInsertionPointName() {
    return "GraphQL Parameter:" + insertationPoint.getName();
  }

  @Override
  public String getBaseValue() {
    return insertationPoint.getValue();
  }

  @Override
  public byte[] buildRequest(byte[] payload) {
    String payloadAsString = helpers.bytesToString(payload);
    GqlEditor editor = new GqlEditor();
    String modifiedRequest = editor.replace(gqlRequest, insertationPoint, payloadAsString);
    logger.log("Param:" + insertationPoint.getName() + ";  Payload:"+payloadAsString+"" );
    byte[] modifiedBody = helpers.stringToBytes(modifiedRequest);
    return ArrayUtils.concat(burpRequest.getHeader(), modifiedBody);
  }

  @Override
  public int[] getPayloadOffsets(byte[] payload) {
    // since the payload is being inserted into a serialized data structure, there aren't any offsets
    // into the request where the payload literally appears
    return null;
  }

  @Override
  public byte getInsertionPointType() {
    return INS_EXTENSION_PROVIDED;
  }
}
