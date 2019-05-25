package extension.gql;

import burp.BurpExtender;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import extension.utils.Logger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

public class GqlVariableParser {

  private static Logger logger = BurpExtender.getLogger();

  public List<GqlVariableInjectionPoint> extractInsertationPoints(String variables){
    if(variables == null || variables.isEmpty()) {
      return new ArrayList<>();
    }

    try{
      JsonParser parser = new JsonParser();
      JsonObject vars = parser.parse(variables).getAsJsonObject();

      List<GqlVariableInjectionPoint> iPoints = new ArrayList<>();
      for (Entry<String, JsonElement> element : vars.entrySet()) {
        String key = element.getKey();
        String value = element.getValue().getAsString();
        iPoints.add(new GqlVariableInjectionPoint(key, value));
      }

      return iPoints;

    }catch (Exception e){
      logger.log("Error while trying to get injection points from variables" + e.getMessage());
      return new ArrayList<>();
    }
  }
}
