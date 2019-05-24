package extension.gql;

import burp.BurpExtender;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import extension.utils.Logger;

public class GqlEditor {

  private static Logger logger = BurpExtender.getLogger();

  public String modify(GqlRequest originalRequest, GqlRequest modifiedRequest){
    JsonObject requestJson = new JsonParser().parse(originalRequest.getRequestBody()).getAsJsonObject();
    modifyProperty(requestJson, GqlRequest.QUERY, modifiedRequest.getQuery());
    modifyProperty(requestJson, GqlRequest.OPERATION_NAME, modifiedRequest.getOperationName());
    modifyVariables(requestJson, modifiedRequest.getVariables());
    return requestJson.toString();
  }

  public String replace(GqlRequest originalRequest, GqlInjectionPoint injectionPoint, String payload){
    String query = originalRequest.getQuery();
    String queryBefore = query.substring(0, injectionPoint.getOffset());
    String queryAfter = query.substring(injectionPoint.getOffset() + injectionPoint.getValue().length());
    String escapedPayload = new Gson().toJson(payload);
    escapedPayload = removeLeadingAndTrailingDoubleQuote(escapedPayload);

    String newQuery = queryBefore + escapedPayload + queryAfter;

    return modify(originalRequest, new GqlRequest(null, newQuery, null, null));
  }

  /**
   * Gson serialisation attaches double quotes that we dont need, they must be removed
   */
  private String removeLeadingAndTrailingDoubleQuote(String escapedPayload) {
    if(escapedPayload.startsWith("\"")){
      escapedPayload = escapedPayload.substring(1);
    }

    if(escapedPayload.endsWith("\"")){
      escapedPayload = escapedPayload.substring(0, escapedPayload.length()-1);
    }
    return escapedPayload;
  }

  private void modifyProperty(JsonObject requestJson, String property, String value) {
    if (value != null) {
      try{
        requestJson.addProperty(property, value);
      }catch (Exception e){
        logger.log("Error while modifying "+property+":" + e.getMessage());
      }
    }
  }

  private void modifyVariables(JsonObject requestJson, String variablesJson) {
    if(variablesJson != null) {
      try{
        JsonObject variablesObj = new JsonParser().parse(variablesJson).getAsJsonObject();
        requestJson.add(GqlRequest.VARIABLES, variablesObj);
      }catch (Exception e){
        logger.log("Error while modifying " + GqlRequest.VARIABLES+":" + e.getMessage());
      }
    }
  }
}
