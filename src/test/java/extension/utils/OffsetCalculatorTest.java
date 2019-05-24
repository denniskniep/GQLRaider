package extension.utils;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.*;

import org.junit.Test;

public class OffsetCalculatorTest {

  @Test
  public void getOffset() {
    String test = "bla1234\n"
        + "test123\n"
        + "myDog";

    String result = getSubstring(test, 1, 4,3);
    assertThat(result, is("123"));
  }

  @Test
  public void getOffset_FirstChar() {
    String test = "bla1\n"
        + "test123\n"
        + "myDog";

    String result = getSubstring(test, 0, 0, 3);
    assertThat(result, is("bla"));
  }

  @Test
  public void getOffset_SecondChar() {
    String test = "bla1\n"
        + "test123\n"
        + "myDog";

    String result = getSubstring(test, 0, 1, 3);
    assertThat(result, is("la1"));
  }

  @Test
  public void getOffset_FirstRowLineEnding() {
    String test = "bla1\n"
        + "test123\n"
        + "myDog";

    String result = getSubstring(test, 0, 4, 1);
    assertThat(result, is("\n"));
  }

  @Test
  public void getOffset_SecondRow() {
    String test = "bla1\n"
        + "test123\n"
        + "myDog";

    String result = getSubstring(test, 1, 0, 1);
    assertThat(result, is("t"));
  }

  @Test
  public void getOffset_LastChar() {
    String test = "bla1\n"
        + "test123\n"
        + "myDog";

    String result =  getSubstring(test, 2, 2, 3);
    assertThat(result, is("Dog"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void getOffset_NoLineError() {
    String test = "bla1\n"
        + "test123\n"
        + "myDog";

    getSubstring(test, 3, 3, 3);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getOffset_NoColumnInLineError() {
    String test = "bla1\n"
        + "test123\n"
        + "myDog";

    getSubstring(test, 1, 8, 1);
  }

  private String getSubstring(String test, int line, int column, int length) {
    OffsetCalculator calc = new OffsetCalculator(test);
    int offset = calc.getOffset(line, column);
    return test.substring(offset, offset+length);
  }
}