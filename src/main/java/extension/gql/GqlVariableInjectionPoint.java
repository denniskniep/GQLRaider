package extension.gql;

public class GqlVariableInjectionPoint {
  private String name;
  private String value;

  public GqlVariableInjectionPoint(String name, String value) {
    this.name = name;
    this.value = value;
  }

  public String getName() {
    return name;
  }

  public String getValue() {
    return value;
  }
}
