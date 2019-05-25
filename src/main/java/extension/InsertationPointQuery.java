package extension;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IScannerInsertionPoint;
import extension.gql.GqlEditor;
import extension.gql.GqlQueryInjectionPoint;
import extension.gql.GqlRequest;
import extension.utils.ArrayUtils;
import extension.utils.Logger;

public class InsertationPointQuery implements IScannerInsertionPoint {

  private static Logger logger = BurpExtender.getLogger();
  private IExtensionHelpers helpers;

  private BurpRequest burpRequest;
  private GqlRequest gqlRequest;
  private GqlQueryInjectionPoint insertationPoint;

  public InsertationPointQuery(IExtensionHelpers helpers, BurpRequest burpRequest, GqlRequest gqlRequest,
      GqlQueryInjectionPoint insertationPoint) {
    this.helpers = helpers;
    this.burpRequest = burpRequest;
    this.gqlRequest = gqlRequest;
    this.insertationPoint = insertationPoint;
  }

  @Override
  public String getInsertionPointName() {
    return "GraphQLQueryParameter:" + insertationPoint.getName();
  }

  @Override
  public String getBaseValue() {
    return insertationPoint.getValue();
  }

  @Override
  public byte[] buildRequest(byte[] payload) {
    String payloadAsString = helpers.bytesToString(payload);
    GqlEditor editor = new GqlEditor();
    String modifiedRequest = editor.replaceInQuery(gqlRequest, insertationPoint, payloadAsString);
    logger.log("ParamQuery:" + insertationPoint.getName() + ";  Payload:" + payloadAsString + "");
    byte[] modifiedBody = helpers.stringToBytes(modifiedRequest);
    return ArrayUtils.concat(burpRequest.getHeader(), modifiedBody);
  }

  @Override
  public int[] getPayloadOffsets(byte[] payload) {
    // since the payload is being inserted into a multiple escaped data structure its a bit tricky to find out the offsets
    return null;
  }

  @Override
  public byte getInsertionPointType() {
    return INS_EXTENSION_PROVIDED;
  }
}
