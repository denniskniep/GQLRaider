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

  private void addJsonToIpoints(JsonElement vars, List<GqlVariableInjectionPoint> iPoints,String prev_key)
  {
    if(vars.isJsonObject()) {
      for (Entry<String, JsonElement> element : vars.getAsJsonObject().entrySet()) {
        String key = element.getKey();
        if (prev_key != "") {

          //use json paths
          key = prev_key + "." + key;
        }

        addJsonToIpoints(element.getValue(), iPoints, key);

      }
    }else if (vars.isJsonArray()) {
      int i = 0;
      for (JsonElement item : vars.getAsJsonArray()) {

        String arraykey = prev_key + String.format("[%d]", i);
        addJsonToIpoints(item, iPoints, arraykey);
        i++;
      }
    }
    else if(vars.isJsonPrimitive()) {
          String value = vars.getAsString();
          iPoints.add(new GqlVariableInjectionPoint(prev_key, value));
        }
  }






  public List<GqlVariableInjectionPoint> extractInsertationPoints(String variables){
    if(variables == null || variables.isEmpty()) {
      return new ArrayList<>();
    }

    try{
      JsonParser parser = new JsonParser();
      JsonObject vars = parser.parse(variables).getAsJsonObject();

      logger.log("Here is the variables: " + variables);

      List<GqlVariableInjectionPoint> iPoints = new ArrayList<>();
      addJsonToIpoints(vars, iPoints,"");

      return iPoints;

    }catch (Exception e){
      logger.log("Error while trying to get injection points from variables" + e.getMessage());
      return new ArrayList<>();
    }
  }
}
