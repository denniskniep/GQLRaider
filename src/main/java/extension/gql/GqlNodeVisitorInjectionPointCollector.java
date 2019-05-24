package extension.gql;

import burp.BurpExtender;
import extension.utils.Logger;
import extension.utils.OffsetCalculator;
import graphql.language.BooleanValue;
import graphql.language.EnumValue;
import graphql.language.FloatValue;
import graphql.language.IntValue;
import graphql.language.NamedNode;
import graphql.language.Node;
import graphql.language.NodeVisitorStub;
import graphql.language.NullValue;
import graphql.language.StringValue;
import graphql.util.TraversalControl;
import graphql.util.TraverserContext;
import java.util.ArrayList;
import java.util.List;

class GqlNodeVisitorInjectionPointCollector extends NodeVisitorStub {

  private static Logger logger = BurpExtender.getLogger();
  private List<GqlInjectionPoint> injectionPoints = new ArrayList<>();
  private OffsetCalculator offsetCalculator;

  public GqlNodeVisitorInjectionPointCollector(String query) {
    this.offsetCalculator = new OffsetCalculator(query);
  }

  public List<GqlInjectionPoint> getInjectionPoints() {
    return injectionPoints;
  }

  @Override
  public TraversalControl visitBooleanValue(BooleanValue node, TraverserContext<Node> context) {
    return addInjectionPoint(node, context, node.isValue());
  }

  @Override
  public TraversalControl visitIntValue(IntValue node, TraverserContext<Node> context) {
    return addInjectionPoint(node, context, node.getValue());
  }

  @Override
  public TraversalControl visitFloatValue(FloatValue node, TraverserContext<Node> context) {
    return addInjectionPoint(node, context, node.getValue());
  }

  @Override
  public TraversalControl visitNullValue(NullValue node, TraverserContext<Node> context) {
    return addInjectionPoint(node, context, null);
  }

  @Override
  public TraversalControl visitStringValue(StringValue node, TraverserContext<Node> context) {
    int TrailingDoubleQuoteCount = 1;
    return addInjectionPoint(context,
        node.getValue(),
        node.getSourceLocation().getLine(),
        node.getSourceLocation().getColumn() + TrailingDoubleQuoteCount);
  }

  @Override
  public TraversalControl visitEnumValue(EnumValue node, TraverserContext<Node> context) {
    return addInjectionPoint(node, context, node.getName());
  }

  private TraversalControl addInjectionPoint(Node node,
      TraverserContext<Node> context,
      Object value){
    return addInjectionPoint(context, value, node.getSourceLocation().getLine(), node.getSourceLocation().getColumn());
  }

  private TraversalControl addInjectionPoint(TraverserContext<Node> context,
      Object value,
      int line,
      int column) {

    if(!context.isVisited()) {
      String name = tryGetName(context);
      String valueAsString = getValue(value);
      int offset = getOffset(line, column);

      GqlInjectionPoint point = new GqlInjectionPoint(name,
          valueAsString,
          line,
          column,
          offset);
      injectionPoints.add(point);
    }
    return TraversalControl.CONTINUE;
  }

  private int getOffset(int line, int column) {
    return offsetCalculator.getOffset(
        line - 1,
        column - 1);
  }

  private String getValue(Object value) {
    return value.toString();
  }

  private String tryGetName(TraverserContext<Node> context) {
    try{
      if (context != null
          && context.getParentContext() != null
          && context.getParentContext().thisNode() != null
          && context.getParentContext().thisNode() instanceof NamedNode) {
        NamedNode namedNode = (NamedNode) context.getParentContext().thisNode();
        return namedNode.getName();
      }
    }catch (Exception e){
      logger.log("Error while try getting the name for an injection point:" + e.getMessage());
    }
    return "";
  }
}
