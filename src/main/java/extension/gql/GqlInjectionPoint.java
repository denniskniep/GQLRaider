package extension.gql;

public class GqlInjectionPoint {
  private String name;
  private String value;
  private int line;
  private int column;
  private int offset;

  public GqlInjectionPoint(String name, String value, int line, int column, int offset) {
    this.name = name;
    this.value = value;
    this.line = line;
    this.column = column;
    this.offset = offset;
  }

  public String getName() {
    return name;
  }

  public String getValue() {
    return value;
  }

  public int getLine() {
    return line;
  }

  public int getColumn() {
    return column;
  }

  public int getOffset() {
    return offset;
  }
}
