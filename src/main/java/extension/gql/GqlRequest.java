package extension.gql;

public class GqlRequest {

  public final static String QUERY = "query";
  public final static String VARIABLES = "variables";
  public final static String OPERATION_NAME = "operationName";

  private String requestBody;
  private String query;
  private String variables;
  private String operationName;

  public GqlRequest() {
  }

  public GqlRequest(String requestBody, String query, String variables, String operationName) {
    this.requestBody = requestBody;
    this.query = query;
    this.variables = variables;
    this.operationName = operationName;
  }

  public String getRequestBody() {
    return requestBody;
  }

  public void setRequestBody(String requestBody) {
    this.requestBody = requestBody;
  }

  public String getQuery() {
    return query;
  }

  public void setQuery(String query) {
    this.query = query;
  }

  public String getVariables() {
    return variables;
  }

  public void setVariables(String variables) {
    this.variables = variables;
  }

  public String getOperationName() {
    return operationName;
  }

  public void setOperationName(String operationName) {
    this.operationName = operationName;
  }
}
