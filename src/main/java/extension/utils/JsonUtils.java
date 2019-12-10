package extension.utils;
import com.google.gson.*;

public class JsonUtils {
    /**
     * Returns a JSON sub-element from the given JsonElement and the given path
     *
     * @param json - a Gson JsonElement
     * @param path - a JSON path, e.g. a.b.c[2].d
     * @return - a sub-element of json according to the given path
     */
    public static JsonElement getJsonElement(JsonElement json, String path){

        String[] parts = path.split("\\.|\\[|\\]");
        JsonElement result = json;

        for (String key : parts) {

            key = key.trim();
            if (key.isEmpty())
                continue;

            if (result == null){
                result = JsonNull.INSTANCE;
                break;
            }

            if (result.isJsonObject()){
                result = ((JsonObject)result).get(key);
            }
            else if (result.isJsonArray()){
                int ix = Integer.valueOf(key) - 1;
                result = ((JsonArray)result).get(ix);
            }
            else break;
        }

        return result;
    }

    public static void setJsonElement(JsonElement json, String path, String payload){

        String[] parts = path.split("\\.|\\[|\\]");
        JsonElement result = json;

        for (String key : parts) {

            key = key.trim();

            if (key.isEmpty())
                continue;

            if (result == null){
                result = JsonNull.INSTANCE;
                break;
            }

            if (result.isJsonObject()){
                if(((JsonObject)result).get(key).isJsonPrimitive())
                {
                    ((JsonObject)result).addProperty(key, payload);
                    return;
                }
                result = ((JsonObject)result).get(key);
            }
            else if (result.isJsonArray()){

                int ix = Integer.valueOf(key) - 1;
                if(((JsonArray)result).get(ix).isJsonPrimitive())
                {
                    ((JsonArray)result).set(1,  new JsonPrimitive(payload));
                    return;
                }
                result = ((JsonArray)result).get(ix);
            }
            else break;
        }

    }
}
