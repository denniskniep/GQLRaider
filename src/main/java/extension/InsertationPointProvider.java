package extension;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScannerInsertionPoint;
import burp.IScannerInsertionPointProvider;
import extension.gql.GqlQueryInjectionPoint;
import extension.gql.GqlQueryParser;
import extension.gql.GqlRequest;
import extension.gql.GqlRequestParser;
import extension.gql.GqlVariableInjectionPoint;
import extension.gql.GqlVariableParser;
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

    List<IScannerInsertionPoint> insertionPoints = new ArrayList<>();
    List<IScannerInsertionPoint> queryPoints = parseInjectionPointsFromQuery(burpRequest, gqlRequest);
    List<IScannerInsertionPoint> varPoints = parseInjectionPointsFromVariables(burpRequest, gqlRequest);
    insertionPoints.addAll(queryPoints);
    insertionPoints.addAll(varPoints);
    return insertionPoints;
  }

  private List<IScannerInsertionPoint> parseInjectionPointsFromQuery(BurpRequest burpRequest, GqlRequest gqlRequest) {
    GqlQueryParser gqlQueryParser = new GqlQueryParser();
    List<GqlQueryInjectionPoint> injectionPoints = gqlQueryParser.extractInsertationPoints(gqlRequest.getQuery());

    List<IScannerInsertionPoint> insertionPoints = new ArrayList<>();
    for (GqlQueryInjectionPoint injectionPoint : injectionPoints) {
      InsertationPointQuery iPoint = new InsertationPointQuery(helpers, burpRequest, gqlRequest, injectionPoint);
      insertionPoints.add(iPoint);
    }
    return insertionPoints;
  }

  private List<IScannerInsertionPoint> parseInjectionPointsFromVariables(BurpRequest burpRequest, GqlRequest gqlRequest) {
    GqlVariableParser gqlVariableParser = new GqlVariableParser();
    List<GqlVariableInjectionPoint> injectionPoints = gqlVariableParser.extractInsertationPoints(gqlRequest.getVariables());

    List<IScannerInsertionPoint> insertionPoints = new ArrayList<>();
    for (GqlVariableInjectionPoint injectionPoint : injectionPoints) {
      InsertationPointVariable iPoint = new InsertationPointVariable(helpers, burpRequest, gqlRequest, injectionPoint);
      insertionPoints.add(iPoint);
    }
    return insertionPoints;
  }
}
