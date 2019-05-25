package extension.gql;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.util.List;
import org.junit.Test;

public class GqlVariableParserTest {
  @Test
  public void oneInjectionPoint() {
    String variables = "{ \"a\":\"b\" }";
    List<GqlVariableInjectionPoint> iPoints = getInjectionPoints(variables);
    assertThat(iPoints.size(), is(1));
    assertInjectionPoint(iPoints.get(0), "a", "b");
  }

  private List<GqlVariableInjectionPoint> getInjectionPoints(String variables) {
    GqlVariableParser parser = new GqlVariableParser();
    return parser.extractInsertationPoints(variables);
  }

  private void assertInjectionPoint(GqlVariableInjectionPoint iPoint, String name, String value) {
    assertThat(iPoint.getName(), is(name));
    assertThat(iPoint.getValue(), is(value));
  }
}