package extension.utils;

public class OffsetCalculator {

  private String text;

  public OffsetCalculator(String text) {
    this.text = text;
  }

  /**
   * Calculates the offset of the position inside a text
   * @param line null-based line index
   * @param column null-based column index
   * @return
   */
  public int getOffset(int line, int column) {
    String[] lines = text.split("\n");
    if (line > lines.length - 1) {
      throw new IllegalArgumentException("Text has no line number " + line);
    }

    if (column > lines[line].length()) {
      throw new IllegalArgumentException("Line " + line + " has no column number " + column);
    }

    int offset = sumLineLengthUntil(lines, line);
    return offset + column;
  }

  private int sumLineLengthUntil(String[] lines, int line) {
    int countForLineFeed = 1;
    int sum = 0;
    for (int i = 0; i < line; i++) {
      sum += lines[i].length() + countForLineFeed;
    }
    return sum;
  }
}
