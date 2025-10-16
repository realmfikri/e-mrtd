package emu.ui;

import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.DatePicker;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.TitledPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Collapsible section that exposes advanced CLI toggles to the UI.
 */
final class AdvancedOptionsPane extends TitledPane {

  private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");

  private final TextField docNumberField = new TextField();
  private final TextField dobField = new TextField();
  private final TextField doeField = new TextField();

  private final TextField canField = new TextField();
  private final TextField pinField = new TextField();
  private final TextField pukField = new TextField();

  private final ComboBox<String> pacePreferenceBox = new ComboBox<>();

  private final TextArea taCvcArea = new TextArea();
  private final TextField taKeyField = new TextField();
  private final DatePicker taDatePicker = new DatePicker();

  private final TextField trustStoreField = new TextField();
  private final TextField taDateOverrideField = new TextField();

  private final CheckBox openComSodBox = new CheckBox("Open COM/SOD");
  private final CheckBox secureComSodBox = new CheckBox("Secure COM/SOD");

  AdvancedOptionsPane() {
    setText("Advanced toggles");
    setCollapsible(true);
    setExpanded(false);

    VBox content = new VBox(12);
    content.setPadding(new Insets(10));

    content.getChildren().add(buildMrzSection());
    content.getChildren().add(buildPaceSection());
    content.getChildren().add(buildPaceProfileSection());
    content.getChildren().add(buildTerminalAuthSection());
    content.getChildren().add(buildPolicySection());

    setContent(content);
  }

  AdvancedOptionsSnapshot snapshot() {
    String taDateValue = null;
    if (taDatePicker.getValue() != null) {
      taDateValue = DATE_FORMATTER.format(taDatePicker.getValue());
    } else if (!taDateOverrideField.getText().isBlank()) {
      taDateValue = taDateOverrideField.getText().trim();
    }

    return new AdvancedOptionsSnapshot(
        trimmed(docNumberField.getText()),
        trimmed(dobField.getText()),
        trimmed(doeField.getText()),
        trimmed(canField.getText()),
        trimmed(pinField.getText()),
        trimmed(pukField.getText()),
        pacePreferenceValue(),
        parseMultiLine(taCvcArea.getText()),
        trimmed(taKeyField.getText()),
        taDateValue,
        trimmed(trustStoreField.getText()),
        openComSodBox.isSelected(),
        secureComSodBox.isSelected());
  }

  private Node buildMrzSection() {
    GridPane grid = new GridPane();
    grid.setHgap(8);
    grid.setVgap(6);

    addRow(grid, 0, new Label("MRZ Document #"), docNumberField);
    addRow(grid, 1, new Label("Date of Birth (YYMMDD)"), dobField);
    addRow(grid, 2, new Label("Date of Expiry (YYMMDD)"), doeField);

    VBox box = new VBox(6);
    Label title = new Label("MRZ inputs");
    title.getStyleClass().add("section-title");
    box.getChildren().addAll(title, grid);
    return box;
  }

  private Node buildPaceSection() {
    GridPane grid = new GridPane();
    grid.setHgap(8);
    grid.setVgap(6);

    addRow(grid, 0, new Label("CAN"), canField);
    addRow(grid, 1, new Label("PIN"), pinField);
    addRow(grid, 2, new Label("PUK"), pukField);

    VBox box = new VBox(6);
    Label title = new Label("PACE secrets");
    title.getStyleClass().add("section-title");
    box.getChildren().addAll(title, grid);
    return box;
  }

  private Node buildPaceProfileSection() {
    pacePreferenceBox.getItems().setAll(
        "Default",
        "AES128",
        "AES192",
        "AES256",
        "GM",
        "IM",
        "OID");
    pacePreferenceBox.getSelectionModel().selectFirst();

    VBox box = new VBox(6);
    Label title = new Label("PACE profile preference");
    title.getStyleClass().add("section-title");
    box.getChildren().addAll(title, pacePreferenceBox);
    return box;
  }

  private Node buildTerminalAuthSection() {
    VBox box = new VBox(6);
    Label title = new Label("Terminal Authentication");
    title.getStyleClass().add("section-title");

    taCvcArea.setPromptText("One path per line");
    taCvcArea.setPrefRowCount(3);

    GridPane grid = new GridPane();
    grid.setHgap(8);
    grid.setVgap(6);

    addRow(grid, 0, new Label("TA CVCs"), taCvcArea);
    addRow(grid, 1, new Label("TA key"), taKeyField);

    HBox dateRow = new HBox(6);
    taDatePicker.setPromptText("Pick date");
    taDateOverrideField.setPromptText("Override (YYYY-MM-DD)");
    HBox.setHgrow(taDateOverrideField, Priority.ALWAYS);
    dateRow.getChildren().addAll(taDatePicker, taDateOverrideField);

    VBox taBox = new VBox(6);
    taBox.getChildren().addAll(grid, new Label("TA date"), dateRow);

    addRow(grid, 2, new Label("Trust store"), trustStoreField);

    box.getChildren().addAll(title, taBox);
    return box;
  }

  private Node buildPolicySection() {
    VBox box = new VBox(6);
    Label title = new Label("Policy toggles");
    title.getStyleClass().add("section-title");
    box.getChildren().addAll(title, openComSodBox, secureComSodBox);
    return box;
  }

  private static void addRow(GridPane grid, int row, Node label, Node input) {
    GridPane.setRowIndex(label, row);
    GridPane.setColumnIndex(label, 0);
    GridPane.setRowIndex(input, row);
    GridPane.setColumnIndex(input, 1);
    grid.getChildren().addAll(label, input);
  }

  private static String trimmed(String value) {
    return value == null ? null : value.trim();
  }

  private String pacePreferenceValue() {
    String selection = pacePreferenceBox.getSelectionModel().getSelectedItem();
    if (selection == null) {
      return null;
    }
    if ("Default".equalsIgnoreCase(selection)) {
      return null;
    }
    return selection;
  }

  private static List<String> parseMultiLine(String value) {
    if (value == null || value.isBlank()) {
      return List.of();
    }
    List<String> tokens = new ArrayList<>();
    for (String line : value.split("\n")) {
      String trimmed = line.trim();
      if (!trimmed.isEmpty()) {
        tokens.addAll(Arrays.stream(trimmed.split(","))
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .collect(Collectors.toList()));
      }
    }
    return List.copyOf(tokens);
  }
}

