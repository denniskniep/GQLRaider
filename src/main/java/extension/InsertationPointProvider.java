package extension;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScannerInsertionPoint;
import burp.IScannerInsertionPointProvider;
import extension.gql.GqlInjectionPoint;
import extension.gql.GqlQueryParser;
import extension.gql.GqlRequest;
import extension.gql.GqlRequestParser;
import java.util.ArrayList;
import java.util.List;

public class InsertationPointProvider implements IScannerInsertionPointProvider {

  private IExtensionHelpers helpers;

  public InsertationPointProvider(IExtensionHelpers helpers) {
    this.helpers = helpers;
  }

  public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse) {
    byte[] request = baseRequestResponse.getRequest();
    BurpRequest burpRequest = BurpRequest.from(request, helpers);

    GqlRequestParser gqlRequestParser = new GqlRequestParser();
    GqlRequest gqlRequest = gqlRequestParser.parse(burpRequest.getBodyAsString());
    GqlQueryParser gqlQueryParser = new GqlQueryParser();
    List<GqlInjectionPoint> injectionPoints = gqlQueryParser.extractInsertationPoints(gqlRequest);

    List<IScannerInsertionPoint> insertionPoints = new ArrayList<>();
    for (GqlInjectionPoint injectionPoint : injectionPoints) {
      InsertationPoint iPoint = new InsertationPoint(helpers, burpRequest, gqlRequest, injectionPoint);
      insertionPoints.add(iPoint);
    }

    return insertionPoints;
  }
}
