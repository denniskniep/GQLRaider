package extension.gql;

import burp.BurpExtender;
import extension.utils.Logger;
import graphql.ExecutionInput;
import graphql.language.Document;
import graphql.language.NodeTraverser;
import graphql.parser.Parser;
import java.util.ArrayList;
import java.util.List;

public class GqlQueryParser {

  private static Logger logger = BurpExtender.getLogger();

  public List<GqlInjectionPoint> extractInsertationPoints(GqlRequest gqlRequest){
    if(gqlRequest.getQuery() == null || gqlRequest.getQuery().isEmpty()) {
      return new ArrayList<>();
    }

    try{
    Document document = parseAsDoument(gqlRequest.getQuery());
    GqlNodeVisitorInjectionPointCollector visitor = new GqlNodeVisitorInjectionPointCollector(gqlRequest.getQuery());
    NodeTraverser nodeTraverser = new NodeTraverser();
    nodeTraverser.depthFirst(visitor, document.getChildren());
    return visitor.getInjectionPoints();
    }catch (Exception e){
      logger.log("Error while trying to get injection points" + e.getMessage());
      return new ArrayList<>();
    }
  }

  private Document parseAsDoument(String query) {
    ExecutionInput gqlRequest = ExecutionInput.newExecutionInput()
        .query(query)
        .build();

    Parser parser = new Parser();
    return parser.parseDocument(gqlRequest.getQuery());
  }
}
