package extension.gql;

import burp.BurpExtender;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import extension.utils.Logger;

public class GqlRequestParser {

  private static Logger logger = BurpExtender.getLogger();

  public GqlRequest parse(String requestBody){
    String query = tryRead(requestBody, GqlRequest.QUERY);
    String variables = tryRead(requestBody, GqlRequest.VARIABLES);
    String operationName = tryRead(requestBody, GqlRequest.OPERATION_NAME);
    return new GqlRequest(requestBody, query, variables, operationName);
  }

  private String tryRead(String json, String attribute) {
    try{
      JsonParser parser = new JsonParser();
      JsonElement element = parser.parse(json).getAsJsonObject().get(attribute);
      if(element instanceof JsonPrimitive){
        return element.getAsString();
      } else if(element instanceof JsonNull){
        return null;
      }
      return element.toString();
    }catch (Exception e){
      logger.log("Error while reading attribute '" + attribute + "':" + e.getMessage());
      return null;
    }
  }
}
