package emu.ui;

import emu.PersonalizationJob;

import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.DatePicker;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.TitledPane;
import javafx.scene.control.TextFormatter;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import javafx.util.converter.IntegerStringConverter;

import java.io.File;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Collapsible section that exposes advanced CLI toggles to the UI.
 */
final class AdvancedOptionsPane extends TitledPane {

  private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");
  private static final Set<Integer> DEFAULT_ISSUER_DATA_GROUPS = PersonalizationJob.defaultEnabledDataGroups();
  private static final List<String> DEFAULT_LIFECYCLE_TARGETS = PersonalizationJob.defaultLifecycleTargets();

  private final ComboBox<String> documentTypeBox = new ComboBox<>();
  private final TextField docNumberField = new TextField();
  private final TextField issuingStateField = new TextField();
  private final TextField nationalityField = new TextField();
  private final TextField primaryIdentifierField = new TextField();
  private final TextField secondaryIdentifierField = new TextField();
  private final TextField dobField = new TextField();
  private final TextField doeField = new TextField();
  private final ComboBox<String> genderBox = new ComboBox<>();

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

  private final List<DataGroupToggle> issuerDataGroupToggles = createDataGroupToggles();
  private final ComboBox<AlgorithmOption> digestAlgorithmBox = new ComboBox<>();
  private final ComboBox<AlgorithmOption> signatureAlgorithmBox = new ComboBox<>();
  private final ComboBox<OpenReadChoice> openReadPolicyBox = new ComboBox<>();
  private final CheckBox lifecycleSimulatorBox = new CheckBox("SIMULATOR");
  private final CheckBox lifecyclePersonalizedBox = new CheckBox("PERSONALIZED");
  private final CheckBox lifecycleLockedBox = new CheckBox("LOCKED");
  private final TextField facePathField = new TextField();
  private final TextField faceWidthField = new TextField();
  private final TextField faceHeightField = new TextField();

  AdvancedOptionsPane() {
    setText("Advanced toggles");
    setCollapsible(true);
    setExpanded(false);

    VBox content = new VBox(12);
    content.setPadding(new Insets(10));

    content.getChildren().add(buildMrzSection());
    content.getChildren().add(buildPaceSection());
    content.getChildren().add(buildPaceProfileSection());
    content.getChildren().add(buildIssuerSection());
    content.getChildren().add(buildTerminalAuthSection());
    content.getChildren().add(buildPolicySection());

    lifecycleSimulatorBox.setSelected(DEFAULT_LIFECYCLE_TARGETS.contains("SIMULATOR"));
    lifecyclePersonalizedBox.setSelected(DEFAULT_LIFECYCLE_TARGETS.contains("PERSONALIZED"));
    lifecycleLockedBox.setSelected(DEFAULT_LIFECYCLE_TARGETS.contains("LOCKED"));

    ScrollPane scrollPane = new ScrollPane(content);
    scrollPane.setFitToWidth(true);
    scrollPane.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);

    setContent(scrollPane);
  }

  void applyMrzSummary(SessionReportViewData.MrzSummary summary) {
    if (summary == null) {
      clearMrzInputs();
      return;
    }

    setComboBoxValue(documentTypeBox, summary.getDocumentType());
    setTextField(docNumberField, summary.getDocumentNumber());
    setTextField(issuingStateField, summary.getIssuingState());
    setTextField(nationalityField, summary.getNationality());
    setTextField(primaryIdentifierField, summary.getPrimaryIdentifier());
    setTextField(secondaryIdentifierField, summary.getSecondaryIdentifier());
    setTextField(dobField, summary.getDateOfBirth());
    setTextField(doeField, summary.getDateOfExpiry());
    setComboBoxValue(genderBox, summary.getGender());
  }

  void clearMrzInputs() {
    setComboBoxValue(documentTypeBox, null);
    setTextField(docNumberField, null);
    setTextField(issuingStateField, null);
    setTextField(nationalityField, null);
    setTextField(primaryIdentifierField, null);
    setTextField(secondaryIdentifierField, null);
    setTextField(dobField, null);
    setTextField(doeField, null);
    setComboBoxValue(genderBox, null);
  }

  AdvancedOptionsSnapshot snapshot() {
    String taDateValue = null;
    if (taDatePicker.getValue() != null) {
      taDateValue = DATE_FORMATTER.format(taDatePicker.getValue());
    } else if (!taDateOverrideField.getText().isBlank()) {
      taDateValue = taDateOverrideField.getText().trim();
    }

    List<Integer> issuerEnable = new ArrayList<>();
    List<Integer> issuerDisable = new ArrayList<>();
    for (DataGroupToggle toggle : issuerDataGroupToggles) {
      if (toggle.checkBox.isSelected() && !toggle.defaultSelected) {
        issuerEnable.add(toggle.dataGroup);
      } else if (!toggle.checkBox.isSelected() && toggle.defaultSelected) {
        issuerDisable.add(toggle.dataGroup);
      }
    }

    return new AdvancedOptionsSnapshot(
        comboValue(documentTypeBox),
        trimmed(docNumberField.getText()),
        trimmed(issuingStateField.getText()),
        trimmed(nationalityField.getText()),
        trimmed(primaryIdentifierField.getText()),
        trimmed(secondaryIdentifierField.getText()),
        trimmed(dobField.getText()),
        trimmed(doeField.getText()),
        comboValue(genderBox),
        trimmed(canField.getText()),
        trimmed(pinField.getText()),
        trimmed(pukField.getText()),
        pacePreferenceValue(),
        parseMultiLine(taCvcArea.getText()),
        trimmed(taKeyField.getText()),
        taDateValue,
        trimmed(trustStoreField.getText()),
        openComSodBox.isSelected(),
        secureComSodBox.isSelected(),
        issuerEnable,
        issuerDisable,
        algorithmValue(digestAlgorithmBox),
        algorithmValue(signatureAlgorithmBox),
        selectedLifecycleTargets(),
        openReadSelection(),
        trimmed(facePathField.getText()),
        parseInteger(faceWidthField),
        parseInteger(faceHeightField));
  }

  private Node buildMrzSection() {
    documentTypeBox.setEditable(true);
    documentTypeBox.getItems().setAll("P<", "ID", "V<", "AC", "C<");
    documentTypeBox.setPromptText("Default (P<)");

    genderBox.setEditable(true);
    genderBox.getItems().setAll("M", "F", "X", "U");
    genderBox.setPromptText("Default (unspecified)");

    GridPane grid = new GridPane();
    grid.setHgap(8);
    grid.setVgap(6);

    addRow(grid, 0, new Label("Document Type"), documentTypeBox);
    addRow(grid, 1, new Label("MRZ Document #"), docNumberField);
    addRow(grid, 2, new Label("Issuing State"), issuingStateField);
    addRow(grid, 3, new Label("Nationality"), nationalityField);
    addRow(grid, 4, new Label("Surname (Primary ID)"), primaryIdentifierField);
    addRow(grid, 5, new Label("Given Names (Secondary ID)"), secondaryIdentifierField);
    addRow(grid, 6, new Label("Date of Birth (YYMMDD)"), dobField);
    addRow(grid, 7, new Label("Date of Expiry (YYMMDD)"), doeField);
    addRow(grid, 8, new Label("Gender"), genderBox);

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

  private Node buildIssuerSection() {
    VBox box = new VBox(6);
    Label title = new Label("Issuer personalization");
    title.getStyleClass().add("section-title");

    Label portraitLabel = new Label("Portrait overrides");
    portraitLabel.getStyleClass().add("section-title");

    facePathField.setPromptText("Override face image (optional)");
    Button browseButton = new Button("Browse…");
    browseButton.setOnAction(event -> {
      FileChooser chooser = new FileChooser();
      chooser.setTitle("Select face image");
      String existing = trimmed(facePathField.getText());
      if (existing != null && !existing.isEmpty()) {
        File current = new File(existing);
        if (current.isDirectory()) {
          chooser.setInitialDirectory(current);
        } else if (current.getParentFile() != null && current.getParentFile().exists()) {
          chooser.setInitialDirectory(current.getParentFile());
        }
      }
      Window window = getScene() != null ? getScene().getWindow() : null;
      File file = chooser.showOpenDialog(window);
      if (file != null) {
        facePathField.setText(file.getAbsolutePath());
      }
    });
    HBox facePathRow = new HBox(6, facePathField, browseButton);
    HBox.setHgrow(facePathField, Priority.ALWAYS);

    faceWidthField.setPromptText("Width");
    faceHeightField.setPromptText("Height");
    faceWidthField.setPrefColumnCount(5);
    faceHeightField.setPrefColumnCount(5);
    faceWidthField.setTextFormatter(integerFormatter());
    faceHeightField.setTextFormatter(integerFormatter());

    Label sizeSeparator = new Label("×");
    sizeSeparator.setStyle("-fx-font-weight: bold;");
    HBox faceSizeBox = new HBox(6, faceWidthField, sizeSeparator, faceHeightField);

    GridPane faceGrid = new GridPane();
    faceGrid.setHgap(8);
    faceGrid.setVgap(6);
    addRow(faceGrid, 0, new Label("Face image"), facePathRow);
    addRow(faceGrid, 1, new Label("Synthetic size"), faceSizeBox);

    Label dataGroupLabel = new Label("Data group inclusion");
    GridPane dgGrid = new GridPane();
    dgGrid.setHgap(8);
    dgGrid.setVgap(6);
    for (int i = 0; i < issuerDataGroupToggles.size(); i++) {
      DataGroupToggle toggle = issuerDataGroupToggles.get(i);
      GridPane.setRowIndex(toggle.checkBox, i / 4);
      GridPane.setColumnIndex(toggle.checkBox, i % 4);
      dgGrid.getChildren().add(toggle.checkBox);
    }

    configureAlgorithmBox(digestAlgorithmBox, PersonalizationJob.defaultDigestAlgorithm());
    configureAlgorithmBox(signatureAlgorithmBox, PersonalizationJob.defaultSignatureAlgorithm());

    GridPane algorithmGrid = new GridPane();
    algorithmGrid.setHgap(8);
    algorithmGrid.setVgap(6);
    addRow(algorithmGrid, 0, new Label("Digest"), digestAlgorithmBox);
    addRow(algorithmGrid, 1, new Label("Signature"), signatureAlgorithmBox);

    HBox lifecycleBox = new HBox(8);
    lifecycleBox.getChildren().addAll(lifecycleSimulatorBox, lifecyclePersonalizedBox, lifecycleLockedBox);

    openReadPolicyBox.getItems().setAll(OpenReadChoice.values());
    openReadPolicyBox.getSelectionModel().select(OpenReadChoice.DEFAULT);

    box.getChildren().addAll(
        title,
        portraitLabel,
        faceGrid,
        dataGroupLabel,
        dgGrid,
        new Label("Algorithms"),
        algorithmGrid,
        new Label("Lifecycle targets"),
        lifecycleBox,
        new Label("Open COM/SOD read policy"),
        openReadPolicyBox);
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

  private void setTextField(TextField field, String value) {
    field.setText(value == null ? "" : value);
  }

  private void setComboBoxValue(ComboBox<String> box, String value) {
    if (value == null || value.isBlank()) {
      box.getSelectionModel().clearSelection();
      if (box.isEditable()) {
        box.getEditor().setText("");
      }
      return;
    }

    if (box.getItems().contains(value)) {
      box.getSelectionModel().select(value);
    } else if (box.isEditable()) {
      box.getSelectionModel().clearSelection();
      box.getEditor().setText(value);
    } else {
      box.getSelectionModel().clearSelection();
    }
  }

  private String comboValue(ComboBox<String> box) {
    String value = box.getValue();
    if (value == null && box.isEditable()) {
      value = box.getEditor().getText();
    }
    value = trimmed(value);
    if (value == null || value.isEmpty()) {
      return null;
    }
    return value;
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

  private List<DataGroupToggle> createDataGroupToggles() {
    List<DataGroupToggle> toggles = new ArrayList<>();
    for (int dg = 2; dg <= 16; dg++) {
      CheckBox box = new CheckBox("DG" + dg);
      boolean selected = DEFAULT_ISSUER_DATA_GROUPS.contains(dg);
      box.setSelected(selected);
      toggles.add(new DataGroupToggle(dg, box, selected));
    }
    return toggles;
  }

  private void configureAlgorithmBox(ComboBox<AlgorithmOption> box, String defaultValue) {
    box.getItems().setAll(
        new AlgorithmOption("Default (" + defaultValue + ")", null),
        new AlgorithmOption("SHA-256", "SHA-256"),
        new AlgorithmOption("SHA-384", "SHA-384"),
        new AlgorithmOption("SHA-512", "SHA-512"),
        new AlgorithmOption("SHA1", "SHA1"));
    box.setEditable(false);
    box.getSelectionModel().selectFirst();
  }

  private static String algorithmValue(ComboBox<AlgorithmOption> box) {
    AlgorithmOption option = box.getSelectionModel().getSelectedItem();
    return option == null ? null : option.value;
  }

  private List<String> selectedLifecycleTargets() {
    List<String> values = new ArrayList<>();
    if (lifecycleSimulatorBox.isSelected()) {
      values.add("SIMULATOR");
    }
    if (lifecyclePersonalizedBox.isSelected()) {
      values.add("PERSONALIZED");
    }
    if (lifecycleLockedBox.isSelected()) {
      values.add("LOCKED");
    }
    return values;
  }

  private Boolean openReadSelection() {
    OpenReadChoice choice = openReadPolicyBox.getSelectionModel().getSelectedItem();
    if (choice == null) {
      return null;
    }
    return choice.value;
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

  private static Integer parseInteger(TextField field) {
    String value = trimmed(field.getText());
    if (value == null || value.isEmpty()) {
      return null;
    }
    try {
      int parsed = Integer.parseInt(value);
      return parsed > 0 ? parsed : null;
    } catch (NumberFormatException ex) {
      return null;
    }
  }

  private TextFormatter<Integer> integerFormatter() {
    return new TextFormatter<>(new IntegerStringConverter(), null, change -> {
      String newText = change.getControlNewText();
      if (newText == null || newText.isEmpty()) {
        return change;
      }
      return newText.matches("\\d*") ? change : null;
    });
  }

  private static final class DataGroupToggle {
    private final int dataGroup;
    private final CheckBox checkBox;
    private final boolean defaultSelected;

    private DataGroupToggle(int dataGroup, CheckBox checkBox, boolean defaultSelected) {
      this.dataGroup = dataGroup;
      this.checkBox = checkBox;
      this.defaultSelected = defaultSelected;
    }
  }

  private static final class AlgorithmOption {
    private final String label;
    private final String value;

    private AlgorithmOption(String label, String value) {
      this.label = label;
      this.value = value;
    }

    @Override
    public String toString() {
      return label;
    }
  }

  private enum OpenReadChoice {
    DEFAULT(null, "Default (CLI behaviour)"),
    OPEN(Boolean.TRUE, "Open (true)"),
    SECURE(Boolean.FALSE, "Secure (false)");

    private final Boolean value;
    private final String label;

    OpenReadChoice(Boolean value, String label) {
      this.value = value;
      this.label = label;
    }

    @Override
    public String toString() {
      return label;
    }
  }
}
