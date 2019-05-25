package extension.gql;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class GqlRequestParserTest {

  @Test
  public void parseRequest_querySet() {
    String requestBody = "{\"operationName\":null,\"variables\":null,\"query\":\"{ me { name } }\"}";
    GqlRequestParser gqlRequestParser = new GqlRequestParser();
    GqlRequest parsed = gqlRequestParser.parse(requestBody);

    assertThat(parsed.getQuery(), is("{ me { name } }"));
    assertThat(parsed.getOperationName(), nullValue());
    assertThat(parsed.getVariables(), nullValue());
  }

  @Test
  public void parseRequest_queryAndVarsSet() {
    String requestBody = "{\"variables\":{\"test\":\"abc\"},\"query\":\"{ me { name } }\"}";
    GqlRequestParser gqlRequestParser = new GqlRequestParser();
    GqlRequest parsed = gqlRequestParser.parse(requestBody);

    assertThat(parsed.getQuery(), is("{ me { name } }"));
    assertThat(parsed.getOperationName(), nullValue());
    assertThat(parsed.getVariables(), is("{\"test\":\"abc\"}"));
  }

  @Test
  public void parseRequest_querySet_noOtherProps() {
    String requestBody = "{\"query\":\"{ me { name } }\"}";
    GqlRequestParser gqlRequestParser = new GqlRequestParser();
    GqlRequest parsed = gqlRequestParser.parse(requestBody);

    assertThat(parsed.getQuery(), is("{ me { name } }"));
    assertThat(parsed.getOperationName(), nullValue());
    assertThat(parsed.getVariables(), nullValue());
  }

  @Test
  public void parseRequest_complex() {
    String requestBody = "{\"query\":\"{ human(id: 1002) { name appearsIn starships { name } } }\"}";
    GqlRequestParser gqlRequestParser = new GqlRequestParser();
    GqlRequest parsed = gqlRequestParser.parse(requestBody);

    assertThat(parsed.getQuery(), is("{ human(id: 1002) { name appearsIn starships { name } } }"));
    assertThat(parsed.getOperationName(), nullValue());
    assertThat(parsed.getVariables(), nullValue());
  }
}
