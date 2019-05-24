package extension.gql;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.List;
import org.junit.Test;

public class GqlEditorTests {

  @Test
  public void modifyVariables() {
    String requestBody = "{\"operationName\":null,\"variables\":{\"abc\":\"123\"},\"query\":\"{ human(id: $abc) { name appearsIn starships { name } } }\"}";
    GqlRequestParser parser = new GqlRequestParser();
    GqlRequest original = parser.parse(requestBody);
    GqlRequest modified  =new GqlRequest(null, null, "{\"abc\":\"456\"}", null);
    GqlEditor editor = new GqlEditor();
    String modifiedRequest = editor.modify(original, modified);
    assertThat(modifiedRequest, is("{\"operationName\":null,\"variables\":{\"abc\":\"456\"},\"query\":\"{ human(id: $abc) { name appearsIn starships { name } } }\"}"));
  }

  @Test
  public void replaceInt() {
    String requestBody = "{\"query\":\"{ human(id:123) { name appearsIn starships { name } } }\"}";
    GqlRequestParser requestParser = new GqlRequestParser();
    GqlRequest original = requestParser.parse(requestBody);

    GqlQueryParser queryParser = new GqlQueryParser();
    List<GqlInjectionPoint> iPoints = queryParser.extractInsertationPoints(original);
    GqlInjectionPoint injectionPoint = iPoints.get(0);

    GqlEditor editor = new GqlEditor();
    String modified = editor.replace(original, injectionPoint, "4567");

    assertThat(modified, is("{\"query\":\"{ human(id:4567) { name appearsIn starships { name } } }\"}"));
  }

  @Test
  public void replaceString() {
    String requestBody = "{\"query\":\"{ human(name: \\\"Hans\\\") { name appearsIn starships { name } } }\"}";
    GqlRequestParser requestParser = new GqlRequestParser();
    GqlRequest original = requestParser.parse(requestBody);

    GqlQueryParser queryParser = new GqlQueryParser();
    List<GqlInjectionPoint> iPoints = queryParser.extractInsertationPoints(original);
    GqlInjectionPoint injectionPoint = iPoints.get(0);

    GqlEditor editor = new GqlEditor();
    String modifiedRequest = editor.replace(original, injectionPoint, "Peter");

    assertThat(modifiedRequest, is("{\"query\":\"{ human(name: \\\"Peter\\\") { name appearsIn starships { name } } }\"}"));
  }

  @Test
  public void replaceStringWithSpecialChars() {
    String requestBody = "{\"query\":\"{ human(name: \\\"Hans\\\") { name appearsIn starships { name } } }\"}";
    GqlRequestParser requestParser = new GqlRequestParser();
    GqlRequest original = requestParser.parse(requestBody);

    GqlQueryParser queryParser = new GqlQueryParser();
    List<GqlInjectionPoint> iPoints = queryParser.extractInsertationPoints(original);
    GqlInjectionPoint injectionPoint = iPoints.get(0);

    GqlEditor editor = new GqlEditor();
    String modifiedRequest = editor.replace(original, injectionPoint, "Pe \"ter");

    assertThat(modifiedRequest, is("{\"query\":\"{ human(name: \\\"Pe \\\\\\\"ter\\\") { name appearsIn starships { name } } }\"}"));
  }
}
