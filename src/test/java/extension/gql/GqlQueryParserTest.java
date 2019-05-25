package extension.gql;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.List;
import org.junit.Test;

public class GqlQueryParserTest {

  @Test
  public void oneInjectionPoint() {
    String query = "{ human(id: 1002) { name appearsIn starships { name } } }";

    List<GqlQueryInjectionPoint> iPoints = getInjectionPoints(query);

    assertThat(iPoints.size(), is(1));
    assertInjectionPoint(iPoints.get(0), "id", "1002", 12);
  }

  @Test
  public void oneInjectionPointWithEum() {
    String query = "{ human(type: BUZZ) { name appearsIn starships { name } } }";

    List<GqlQueryInjectionPoint> iPoints = getInjectionPoints(query);

    assertThat(iPoints.size(), is(1));
    assertInjectionPoint(iPoints.get(0), "type", "BUZZ", 14);
  }

  @Test
  public void name() {
    String query = "query {\n"
        + "  hero(episode: 1, x: true) {\n"
        + "    name\n"
        + "    friends(name: \"my\"\n"
        + "            id: 500) {\n"
        + "      name\n"
        + "    }\n"
        + "  }\n"
        + "}";

    List<GqlQueryInjectionPoint> iPoints = getInjectionPoints(query);

    assertThat(iPoints.size(), is(4));
    assertInjectionPoint(iPoints.get(0), "episode", "1", 24);
    assertInjectionPoint(iPoints.get(1), "x", "true", 30);
    assertInjectionPoint(iPoints.get(2), "name", "my", 66);
    assertInjectionPoint(iPoints.get(3), "id", "500", 86);
  }

  private List<GqlQueryInjectionPoint> getInjectionPoints(String query) {
    GqlQueryParser parser = new GqlQueryParser();
    return parser.extractInsertationPoints(query);
  }

  private void assertInjectionPoint(GqlQueryInjectionPoint iPoint, String name, String value, int offset) {
    assertThat(iPoint.getName(), is(name));
    assertThat(iPoint.getValue(), is(value));
    assertThat(iPoint.getOffset(), is(offset));
  }
}