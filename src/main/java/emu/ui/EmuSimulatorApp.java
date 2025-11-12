package emu.ui;

import emu.IssuerSimulator;
import emu.PersonalizationJob;
import emu.SessionReport;
import emu.SimLogCategory;
import emu.SimPhase;
import emu.reader.RealPassportReaderTask;
import emu.reader.RealPassportSnapshot;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.binding.Bindings;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Tooltip;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;
import javafx.util.Callback;
import org.jmrtd.BACKey;
import org.jmrtd.lds.icao.MRZInfo;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public final class EmuSimulatorApp extends Application {

  private static final DateTimeFormatter REPORT_TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

  private final ScenarioRunner runner = new ScenarioRunner();
  private final AdvancedOptionsPane advancedOptionsPane = new AdvancedOptionsPane();

  private Stage primaryStage;

  private final ObservableList<LogEntry> logEntries = FXCollections.observableArrayList();
  private final FilteredList<LogEntry> filteredLogs = new FilteredList<>(logEntries);
  private final ListView<LogEntry> logListView = new ListView<>(filteredLogs);
  private final ToggleGroup logFilterGroup = new ToggleGroup();
  private final Label statusLabel = new Label("Ready");
  private final Button copyCliButton = new Button("Copy CLI");
  private final Button copySessionInfoButton = new Button("Copy session info");
  private final Button exportButton = new Button("Export session");
  private final Button runDoc9303Button = new Button("Run ICAO Doc 9303 flow");
  private final Button runAllButton = new Button("Run all tests");
  private final Label scenarioDescription = new Label("Select a scenario to see details.");

  private TabPane resultTabs;
  private Tab issuerTab;
  private Tab cardDetailsTab;
  private final TextField realReaderDocumentNumberField = new TextField();
  private final TextField realReaderDateOfBirthField = new TextField();
  private final TextField realReaderDateOfExpiryField = new TextField();
  private final ProgressIndicator realReaderProgress = new ProgressIndicator();
  private final Label verdictValue = valueLabel();
  private final Label smModeValue = valueLabel();
  private final Label paceValue = valueLabel();
  private final Label caValue = valueLabel();
  private final Label aaValue = valueLabel();
  private final Label terminalAuthValue = valueLabel();

  private final Label issuerOutputDirectoryValue = multilineValueLabel();
  private final Label issuerManifestValue = multilineValueLabel();
  private final Label issuerLifecycleValue = multilineValueLabel();
  private final Label issuerCscaValue = multilineValueLabel();
  private final Label issuerDscValue = multilineValueLabel();
  private final Label issuerPassiveAuthVerdictValue = valueLabel();
  private final Label issuerPassiveAuthDigestValue = valueLabel();
  private final Label issuerPassiveAuthDataGroupsValue = multilineValueLabel();
  private final Label issuerPassiveAuthTrustIssuesValue = multilineValueLabel();
  private final Label issuerFaceSourceValue = multilineValueLabel();
  private final Label issuerFacePreviewPathValue = multilineValueLabel();
  private final ImageView issuerFacePreviewImage = createPreviewImageView(320);

  private final Label cardMrzDocumentNumberValue = valueLabel();
  private final Label terminalMrzDocumentNumberValue = valueLabel();
  private final Label cardMrzIssuingStateValue = valueLabel();
  private final Label terminalMrzIssuingStateValue = valueLabel();
  private final Label cardMrzNationalityValue = valueLabel();
  private final Label terminalMrzNationalityValue = valueLabel();
  private final Label cardMrzDateOfBirthValue = valueLabel();
  private final Label terminalMrzDateOfBirthValue = valueLabel();
  private final Label cardMrzDateOfExpiryValue = valueLabel();
  private final Label terminalMrzDateOfExpiryValue = valueLabel();
  private final Label cardMrzPrimaryIdentifierValue = multilineValueLabel();
  private final Label terminalMrzPrimaryIdentifierValue = multilineValueLabel();
  private final Label cardMrzSecondaryIdentifierValue = multilineValueLabel();
  private final Label terminalMrzSecondaryIdentifierValue = multilineValueLabel();

  private final Label cardTransportValue = valueLabel();
  private final Label terminalTransportValue = valueLabel();
  private final Label cardSecureMessagingModeValue = valueLabel();
  private final Label terminalSecureMessagingModeValue = valueLabel();
  private final Label cardPaceProfilesValue = multilineValueLabel();
  private final Label terminalPaceStatusValue = valueLabel();
  private final Label cardChipAuthProfileValue = valueLabel();
  private final Label terminalChipAuthStatusValue = valueLabel();
  private final Label cardActiveAuthProfileValue = valueLabel();
  private final Label terminalActiveAuthStatusValue = valueLabel();

  private final Label cardDigestAlgorithmValue = valueLabel();
  private final Label terminalDigestAlgorithmValue = valueLabel();
  private final Label cardProvisionedDataGroupsValue = multilineValueLabel();
  private final Label terminalPaDataGroupsValue = multilineValueLabel();
  private final Label cardPaSignerValue = valueLabel();
  private final Label terminalPaSignerValue = multilineValueLabel();
  private final Label cardPaChainValue = valueLabel();
  private final Label terminalPaChainValue = multilineValueLabel();
  private final ImageView cardPortraitImage = createPreviewImageView(240);
  private final ImageView terminalFacePreviewImage = createPreviewImageView(240);

  private final ListView<String> dgListView = new ListView<>();
  private final Label dg3ReadableValue = valueLabel();
  private final Label dg4ReadableValue = valueLabel();
  private final EnumMap<SimPhase, Label> phaseLabels = new EnumMap<>(SimPhase.class);
  private final Label securityContent = new Label("Select a scenario to view a Doc 9303–aligned security explanation.");
  private final List<SimPhase> phaseOrder = List.of(
      SimPhase.CONNECTING,
      SimPhase.AUTHENTICATING,
      SimPhase.READING,
      SimPhase.VERIFYING,
      SimPhase.COMPLETE);

  private static final int MAX_LOG_ENTRIES = 2000;
  private static final String ISSUER_PLACEHOLDER = "(issuer not run)";
  private static final String READER_PLACEHOLDER = "(reader not run)";
  private static final String DG1_NOT_READ_PLACEHOLDER = "(DG1 not read)";

  private Task<ScenarioResult> currentTask;
  private Task<RealPassportSnapshot> currentReaderTask;
  private RealPassportSnapshot lastRealPassportSnapshot;
  private List<String> lastCommands = List.of();
  private SessionReport lastReport;
  private IssuerSimulator.Result lastIssuerResult;
  private SimPhase currentPhase = SimPhase.CONNECTING;
  private Path lastReportPath;
  private ScenarioResult lastScenarioResult;
  private Throwable lastScenarioException;
  private Runnable afterScenarioCallback;
  private BatchRunState batchRunState;
  private VBox scenarioButtonsBox;

  @Override
  public void start(Stage stage) {
    this.primaryStage = stage;
    BorderPane root = new BorderPane();
    root.setLeft(buildScenarioPane());
    root.setCenter(buildResultPane());
    root.setBottom(buildStatusBar());

    Scene scene = new Scene(root, 1280, 720);
    stage.setTitle("eMRTD Scenario Runner");
    stage.setScene(scene);
    stage.show();
  }

  @Override
  public void stop() {
    if (currentTask != null) {
      currentTask.cancel(true);
    }
  }

  private VBox buildScenarioPane() {
    VBox container = new VBox(12);
    container.setPadding(new Insets(12));
    container.setPrefWidth(320);

    Label header = new Label("Scenario presets");
    header.getStyleClass().add("header-label");

    scenarioButtonsBox = new VBox(8);
    for (ScenarioPreset preset : ScenarioPresets.all()) {
      Button button = new Button(preset.getName());
      button.setMaxWidth(Double.MAX_VALUE);
      button.setWrapText(true);
      button.setTooltip(new Tooltip(preset.getDescription()));
      button.setOnAction(e -> runScenario(preset));
      scenarioButtonsBox.getChildren().add(button);
    }

    ScenarioPreset icaoPreset = ScenarioPresets.icaoDoc9303();
    runDoc9303Button.setMaxWidth(Double.MAX_VALUE);
    runDoc9303Button.setWrapText(true);
    runDoc9303Button.setTooltip(new Tooltip(icaoPreset.getDescription()));
    runDoc9303Button.setOnAction(e -> runScenario(icaoPreset));

    runAllButton.setMaxWidth(Double.MAX_VALUE);
    runAllButton.setOnAction(e -> runAllScenarios());

    ScrollPane scrollPane = new ScrollPane(scenarioButtonsBox);
    scrollPane.setFitToWidth(true);
    scrollPane.setPrefHeight(400);

    scenarioDescription.setWrapText(true);
    scenarioDescription.setPadding(new Insets(8, 0, 0, 0));

    container.getChildren().addAll(header, runDoc9303Button, runAllButton, scrollPane, scenarioDescription, advancedOptionsPane);
    VBox.setVgrow(scrollPane, Priority.ALWAYS);
    VBox.setVgrow(advancedOptionsPane, Priority.ALWAYS);
    advancedOptionsPane.setMaxHeight(Double.MAX_VALUE);

    return container;
  }

  private VBox buildResultPane() {
    VBox container = new VBox(12);
    container.setPadding(new Insets(12));
    HBox stepper = buildStepper();
    TabPane tabs = buildResultTabs();
    container.getChildren().addAll(stepper, tabs);
    VBox.setVgrow(tabs, Priority.ALWAYS);
    return container;
  }

  private HBox buildStepper() {
    HBox stepper = new HBox(16);
    stepper.setAlignment(Pos.CENTER_LEFT);
    for (SimPhase phase : phaseOrder) {
      Label label = new Label(formatPhaseLabel(phase, "○"));
      label.getStyleClass().add("stepper-label");
      phaseLabels.put(phase, label);
      stepper.getChildren().add(label);
    }
    return stepper;
  }

  private TabPane buildResultTabs() {
    resultTabs = new TabPane();
    resultTabs.getTabs().add(buildSummaryTab());
    issuerTab = buildIssuerTab();
    resultTabs.getTabs().add(issuerTab);
    clearIssuerTab();
    cardDetailsTab = buildCardDetailsTab();
    resultTabs.getTabs().add(cardDetailsTab);
    clearCardDetailsTab();
    resultTabs.getTabs().add(buildDataGroupsTab());
    resultTabs.getTabs().add(buildRealReaderTab());
    resultTabs.getTabs().add(buildLogTab());
    resultTabs.getTabs().add(buildSecurityTab());
    return resultTabs;
  }

  private Tab buildRealReaderTab() {
    VBox container = new VBox(12);
    container.setPadding(new Insets(16));

    Label header = new Label("Read a real passport");
    header.getStyleClass().add("header-label");

    Label instructions = new Label(
        "Enter the document number, date of birth, and date of expiry from the MRZ, "
            + "then place a passport on a connected NFC reader.");
    instructions.setWrapText(true);

    GridPane form = new GridPane();
    form.setHgap(12);
    form.setVgap(12);

    Label docLabel = new Label("Document number");
    realReaderDocumentNumberField.setPromptText("123456789");
    realReaderDocumentNumberField.setPrefColumnCount(12);
    form.add(docLabel, 0, 0);
    form.add(realReaderDocumentNumberField, 1, 0);

    Label dobLabel = new Label("Date of birth (YYMMDD)");
    realReaderDateOfBirthField.setPromptText("YYMMDD");
    realReaderDateOfBirthField.setPrefColumnCount(8);
    form.add(dobLabel, 0, 1);
    form.add(realReaderDateOfBirthField, 1, 1);

    Label doeLabel = new Label("Date of expiry (YYMMDD)");
    realReaderDateOfExpiryField.setPromptText("YYMMDD");
    realReaderDateOfExpiryField.setPrefColumnCount(8);
    form.add(doeLabel, 0, 2);
    form.add(realReaderDateOfExpiryField, 1, 2);

    Button readButton = new Button("Read passport");
    readButton.setOnAction(e -> startRealPassportRead());

    realReaderProgress.setMaxSize(32, 32);
    realReaderProgress.setProgress(ProgressIndicator.INDETERMINATE_PROGRESS);
    realReaderProgress.setVisible(false);
    realReaderProgress.setManaged(false);

    readButton.disableProperty().bind(realReaderProgress.visibleProperty());

    HBox controls = new HBox(12, readButton, realReaderProgress);
    controls.setAlignment(Pos.CENTER_LEFT);

    container.getChildren().addAll(header, instructions, form, controls);

    Tab tab = new Tab("Real Reader", container);
    tab.setClosable(false);
    return tab;
  }

  private void startRealPassportRead() {
    if (currentReaderTask != null && currentReaderTask.isRunning()) {
      statusLabel.setText("A passport read is already in progress; please wait");
      return;
    }
    if (currentTask != null && currentTask.isRunning()) {
      statusLabel.setText("Finish the running scenario before reading a real passport");
      return;
    }

    String documentNumber = trimToNull(realReaderDocumentNumberField.getText());
    String dateOfBirth = trimToNull(realReaderDateOfBirthField.getText());
    String dateOfExpiry = trimToNull(realReaderDateOfExpiryField.getText());

    if (documentNumber == null || dateOfBirth == null || dateOfExpiry == null) {
      showAlert(Alert.AlertType.WARNING, "Missing MRZ values", "Please provide all MRZ fields before reading a passport.");
      statusLabel.setText("Enter MRZ values before starting a read");
      return;
    }

    documentNumber = documentNumber.replace(" ", "").toUpperCase(Locale.ROOT);
    dateOfBirth = dateOfBirth.replace(" ", "");
    dateOfExpiry = dateOfExpiry.replace(" ", "");

    try {
      new BACKey(documentNumber, dateOfBirth, dateOfExpiry);
    } catch (IllegalArgumentException ex) {
      showAlert(Alert.AlertType.ERROR, "Invalid MRZ values", ex.getMessage());
      statusLabel.setText("Invalid MRZ values");
      return;
    }

    RealPassportReaderTask task = new RealPassportReaderTask(
        null,
        0,
        documentNumber,
        dateOfBirth,
        dateOfExpiry,
        message -> Platform.runLater(() -> addLogEntry(SimLogCategory.GENERAL, "Real Reader", message)));

    lastRealPassportSnapshot = null;
    currentReaderTask = task;
    addLogEntry(SimLogCategory.GENERAL, "Real Reader", "Starting passport read");

    realReaderProgress.progressProperty().unbind();
    realReaderProgress.visibleProperty().unbind();
    realReaderProgress.managedProperty().unbind();
    statusLabel.textProperty().unbind();

    realReaderProgress.setProgress(ProgressIndicator.INDETERMINATE_PROGRESS);
    realReaderProgress.progressProperty().bind(task.progressProperty());
    realReaderProgress.visibleProperty().bind(task.runningProperty());
    realReaderProgress.managedProperty().bind(task.runningProperty());
    statusLabel.textProperty().bind(task.messageProperty());

    task.setOnSucceeded(evt -> {
      realReaderProgress.progressProperty().unbind();
      realReaderProgress.visibleProperty().unbind();
      realReaderProgress.managedProperty().unbind();
      statusLabel.textProperty().unbind();
      realReaderProgress.setVisible(false);
      realReaderProgress.setManaged(false);
      currentReaderTask = null;

      RealPassportSnapshot data = task.getValue();
      if (data != null && data.isValid()) {
        handleRealPassportData(data);
        statusLabel.setText("Passport read complete");
        addLogEntry(SimLogCategory.GENERAL, "Real Reader", "Passport read complete");
      } else {
        statusLabel.setText("Passport read complete (no data)");
        showAlert(Alert.AlertType.INFORMATION, "No data", "The passport read finished but returned no MRZ data.");
      }
    });

    task.setOnFailed(evt -> {
      realReaderProgress.progressProperty().unbind();
      realReaderProgress.visibleProperty().unbind();
      realReaderProgress.managedProperty().unbind();
      statusLabel.textProperty().unbind();
      realReaderProgress.setVisible(false);
      realReaderProgress.setManaged(false);
      currentReaderTask = null;

      Throwable ex = task.getException();
      String message = ex != null ? ex.getMessage() : "Unknown error";
      statusLabel.setText("Passport read failed");
      addLogEntry(SimLogCategory.GENERAL, "Real Reader", "Passport read failed: " + message);
      showAlert(Alert.AlertType.ERROR, "Passport read failed", message);
    });

    Thread thread = new Thread(task, "real-passport-reader");
    thread.setDaemon(true);
    thread.start();
  }

  private void handleRealPassportData(RealPassportSnapshot data) {
    lastRealPassportSnapshot = data;
    SessionReportViewData.MrzSummary mrzSummary = buildMrzSummary(data);

    List<Integer> presentDataGroups = new ArrayList<>();
    if (data.mrz() != null && !data.mrz().isBlank()) {
      presentDataGroups.add(1);
    }

    String previewPathString = null;
    byte[] imageBytes = data.safeImageBytes();
    if (imageBytes != null && imageBytes.length > 0) {
      try {
        Path facesDir = Paths.get("target", "ui-session", "faces");
        Files.createDirectories(facesDir);
        String extension = facePreviewExtension(data.imageMime());
        String fileName = "terminal-face-" + REPORT_TIMESTAMP.format(LocalDateTime.now()) + '.' + extension;
        Path previewPath = facesDir.resolve(fileName);
        Files.write(previewPath, imageBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        previewPathString = previewPath.toAbsolutePath().toString();
        presentDataGroups.add(2);
      } catch (IOException ex) {
        addLogEntry(SimLogCategory.GENERAL, "Real Reader", "Unable to write face preview: " + ex.getMessage());
      }
    }

    SessionReportViewData viewData = new SessionReportViewData(
        "Contactless",   // transport
        "BAC",           // secureMessagingMode
        false,            // paceAttempted
        false,            // paceEstablished
        false,            // caEstablished
        false,            // activeAuthEnabled
        false,            // activeAuthSupported
        false,            // activeAuthVerified
        null,             // activeAuthAlgorithm
        null,             // passiveAuthVerdict
        null,             // passiveAuthAlgorithm
        List.of(),        // passiveAuthOkDataGroups
        List.of(),        // passiveAuthBadDataGroups
        List.of(),        // passiveAuthMissingDataGroups
        List.of(),        // passiveAuthLockedDataGroups
        null,             // passiveAuthSigner
        null,             // passiveAuthChainStatus
        mrzSummary,
        presentDataGroups,
        false,            // dg3Readable
        false,            // dg4Readable
        previewPathString,
        null,
        false,            // terminalAuthAttempted
        false,            // terminalAuthSucceeded
        false,            // terminalAuthDg3Unlocked
        false,            // terminalAuthDg4Unlocked
        null,             // terminalAuthRole
        null,             // terminalAuthRights
        List.of());       // terminalAuthWarnings

    updateSummary(viewData);
    updateDataGroups(viewData);
    updateCardDetailsTab(viewData, lastIssuerResult);

    if (resultTabs != null && cardDetailsTab != null) {
      resultTabs.getSelectionModel().select(cardDetailsTab);
    }
  }

  private Tab buildSummaryTab() {
    GridPane grid = new GridPane();
    grid.setHgap(12);
    grid.setVgap(12);
    grid.setPadding(new Insets(16));

    addSummaryRow(grid, 0, "Passive Auth verdict", verdictValue);
    addSummaryRow(grid, 1, "Secure messaging", smModeValue);
    addSummaryRow(grid, 2, "PACE", paceValue);
    addSummaryRow(grid, 3, "Chip Authentication", caValue);
    addSummaryRow(grid, 4, "Active Authentication", aaValue);
    addSummaryRow(grid, 5, "Terminal Authentication", terminalAuthValue);

    Tab tab = new Tab("Summary", grid);
    tab.setClosable(false);
    return tab;
  }

  private Tab buildIssuerTab() {
    GridPane grid = new GridPane();
    grid.setHgap(12);
    grid.setVgap(12);
    grid.setPadding(new Insets(16));

    addSummaryRow(grid, 0, "Output directory", issuerOutputDirectoryValue);
    addSummaryRow(grid, 1, "Manifest", issuerManifestValue);
    addSummaryRow(grid, 2, "Lifecycle targets", issuerLifecycleValue);
    addSummaryRow(grid, 3, "CSCA anchor", issuerCscaValue);
    addSummaryRow(grid, 4, "DSC certificate", issuerDscValue);
    addSummaryRow(grid, 5, "Passive Auth verdict", issuerPassiveAuthVerdictValue);
    addSummaryRow(grid, 6, "Digest algorithm", issuerPassiveAuthDigestValue);
    addSummaryRow(grid, 7, "Data group issues", issuerPassiveAuthDataGroupsValue);
    addSummaryRow(grid, 8, "Trust store issues", issuerPassiveAuthTrustIssuesValue);
    addSummaryRow(grid, 9, "Portrait source", issuerFaceSourceValue);
    addSummaryRow(grid, 10, "Face preview", issuerFacePreviewPathValue);

    issuerFacePreviewImage.setPreserveRatio(true);
    issuerFacePreviewImage.setFitWidth(320);
    issuerFacePreviewImage.setSmooth(true);

    Label faceHeader = new Label("Face preview image");
    VBox facePreviewBox = new VBox(6, faceHeader, issuerFacePreviewImage);
    facePreviewBox.setPadding(new Insets(0, 0, 16, 0));
    facePreviewBox.visibleProperty().bind(issuerFacePreviewImage.imageProperty().isNotNull());
    facePreviewBox.managedProperty().bind(facePreviewBox.visibleProperty());

    VBox container = new VBox(12, grid, facePreviewBox);
    ScrollPane scrollPane = new ScrollPane(container);
    scrollPane.setFitToWidth(true);

    Tab tab = new Tab("Issuer Output", scrollPane);
    tab.setClosable(false);
    tab.setDisable(true);
    return tab;
  }

  private Tab buildCardDetailsTab() {
    VBox container = new VBox(12);
    container.setPadding(new Insets(16));

    Label portraitHeader = new Label("Portrait previews");
    portraitHeader.getStyleClass().add("header-label");

    Label cardPortraitHeader = new Label("Issuer portrait");
    VBox cardPortraitBox = new VBox(6, cardPortraitHeader, cardPortraitImage);
    cardPortraitBox.visibleProperty().bind(cardPortraitImage.imageProperty().isNotNull());
    cardPortraitBox.managedProperty().bind(cardPortraitBox.visibleProperty());

    Label terminalPortraitHeader = new Label("Terminal capture");
    VBox terminalPortraitBox = new VBox(6, terminalPortraitHeader, terminalFacePreviewImage);
    terminalPortraitBox.visibleProperty().bind(terminalFacePreviewImage.imageProperty().isNotNull());
    terminalPortraitBox.managedProperty().bind(terminalPortraitBox.visibleProperty());

    HBox portraitRow = new HBox(24, cardPortraitBox, terminalPortraitBox);
    portraitRow.setAlignment(Pos.CENTER_LEFT);
    portraitRow.visibleProperty().bind(
        Bindings.or(cardPortraitBox.visibleProperty(), terminalPortraitBox.visibleProperty()));
    portraitRow.managedProperty().bind(portraitRow.visibleProperty());
    portraitHeader.visibleProperty().bind(portraitRow.visibleProperty());
    portraitHeader.managedProperty().bind(portraitRow.visibleProperty());

    Label mrzHeader = new Label("MRZ (DG1)");
    mrzHeader.getStyleClass().add("header-label");
    GridPane mrzGrid = createComparisonGrid();
    addComparisonHeaders(mrzGrid);
    addComparisonRow(mrzGrid, 1, "Document number", cardMrzDocumentNumberValue, terminalMrzDocumentNumberValue);
    addComparisonRow(mrzGrid, 2, "Issuing state", cardMrzIssuingStateValue, terminalMrzIssuingStateValue);
    addComparisonRow(mrzGrid, 3, "Nationality", cardMrzNationalityValue, terminalMrzNationalityValue);
    addComparisonRow(mrzGrid, 4, "Date of birth", cardMrzDateOfBirthValue, terminalMrzDateOfBirthValue);
    addComparisonRow(mrzGrid, 5, "Date of expiry", cardMrzDateOfExpiryValue, terminalMrzDateOfExpiryValue);
    addComparisonRow(mrzGrid, 6, "Primary identifier", cardMrzPrimaryIdentifierValue, terminalMrzPrimaryIdentifierValue);
    addComparisonRow(mrzGrid, 7, "Secondary identifier", cardMrzSecondaryIdentifierValue, terminalMrzSecondaryIdentifierValue);

    Label smHeader = new Label("Secure messaging & authentication");
    smHeader.getStyleClass().add("header-label");
    GridPane smGrid = createComparisonGrid();
    addComparisonHeaders(smGrid);
    addComparisonRow(smGrid, 1, "Transport", cardTransportValue, terminalTransportValue);
    addComparisonRow(smGrid, 2, "Secure messaging", cardSecureMessagingModeValue, terminalSecureMessagingModeValue);
    addComparisonRow(smGrid, 3, "PACE profiles / status", cardPaceProfilesValue, terminalPaceStatusValue);
    addComparisonRow(smGrid, 4, "Chip Authentication", cardChipAuthProfileValue, terminalChipAuthStatusValue);
    addComparisonRow(smGrid, 5, "Active Authentication", cardActiveAuthProfileValue, terminalActiveAuthStatusValue);

    Label paHeader = new Label("Passive authentication & DG hashes");
    paHeader.getStyleClass().add("header-label");
    GridPane paGrid = createComparisonGrid();
    addComparisonHeaders(paGrid);
    addComparisonRow(paGrid, 1, "Digest algorithm", cardDigestAlgorithmValue, terminalDigestAlgorithmValue);
    addComparisonRow(paGrid, 2, "Provisioned DG hashes", cardProvisionedDataGroupsValue, terminalPaDataGroupsValue);
    addComparisonRow(paGrid, 3, "Signer", cardPaSignerValue, terminalPaSignerValue);
    addComparisonRow(paGrid, 4, "Chain status", cardPaChainValue, terminalPaChainValue);

    container.getChildren().addAll(
        portraitHeader,
        portraitRow,
        mrzHeader,
        mrzGrid,
        smHeader,
        smGrid,
        paHeader,
        paGrid);

    ScrollPane scrollPane = new ScrollPane(container);
    scrollPane.setFitToWidth(true);
    scrollPane.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);

    Tab tab = new Tab("Card vs Terminal", scrollPane);
    tab.setClosable(false);
    tab.setDisable(true);
    return tab;
  }

  private Tab buildDataGroupsTab() {
    VBox box = new VBox(8);
    box.setPadding(new Insets(16));

    Label presentLabel = new Label("Present Data Groups");
    dgListView.setPrefHeight(200);

    GridPane readabilityGrid = new GridPane();
    readabilityGrid.setHgap(12);
    readabilityGrid.setVgap(8);
    addSummaryRow(readabilityGrid, 0, "DG3 readable", dg3ReadableValue);
    addSummaryRow(readabilityGrid, 1, "DG4 readable", dg4ReadableValue);

    box.getChildren().addAll(presentLabel, dgListView, readabilityGrid);

    Tab tab = new Tab("Data Groups", box);
    tab.setClosable(false);
    return tab;
  }

  private Tab buildLogTab() {
    HBox filters = new HBox(8);
    filters.setAlignment(Pos.CENTER_LEFT);
    RadioButton allButton = new RadioButton("All");
    allButton.setToggleGroup(logFilterGroup);
    allButton.setUserData(null);
    allButton.setSelected(true);
    RadioButton apduButton = new RadioButton("APDU");
    apduButton.setToggleGroup(logFilterGroup);
    apduButton.setUserData(SimLogCategory.APDU);
    RadioButton securityButton = new RadioButton("Security");
    securityButton.setToggleGroup(logFilterGroup);
    securityButton.setUserData(SimLogCategory.SECURITY);
    filters.getChildren().addAll(new Label("Filter:"), allButton, apduButton, securityButton);

    logListView.setCellFactory(createLogCellFactory());
    logListView.setPlaceholder(new Label("Logs will appear here during execution."));

    VBox container = new VBox(8, filters, logListView);
    VBox.setVgrow(logListView, Priority.ALWAYS);

    logFilterGroup.selectedToggleProperty().addListener((obs, oldToggle, newToggle) -> {
      if (newToggle == null) {
        filteredLogs.setPredicate(log -> true);
      } else {
        SimLogCategory category = (SimLogCategory) newToggle.getUserData();
        if (category == null) {
          filteredLogs.setPredicate(log -> true);
        } else {
          filteredLogs.setPredicate(log -> log.getCategory() == category);
        }
      }
    });

    Tab tab = new Tab("Technical Log", container);
    tab.setClosable(false);
    return tab;
  }

  private Tab buildSecurityTab() {
    securityContent.setWrapText(true);
    securityContent.setPadding(new Insets(16));
    ScrollPane scrollPane = new ScrollPane(securityContent);
    scrollPane.setFitToWidth(true);

    Tab tab = new Tab("Security Explained", scrollPane);
    tab.setClosable(false);
    return tab;
  }

  private HBox buildStatusBar() {
    HBox bar = new HBox(12);
    bar.setPadding(new Insets(8, 12, 8, 12));
    bar.setAlignment(Pos.CENTER_LEFT);

    HBox.setHgrow(statusLabel, Priority.ALWAYS);
    statusLabel.setMaxWidth(Double.MAX_VALUE);

    copyCliButton.setDisable(true);
    copyCliButton.setOnAction(e -> copyLastCommands());
    copySessionInfoButton.setDisable(true);
    copySessionInfoButton.setOnAction(e -> copySessionInfo());
    exportButton.setDisable(true);
    exportButton.setOnAction(e -> exportSession());

    bar.getChildren().addAll(statusLabel, copyCliButton, copySessionInfoButton, exportButton);
    return bar;
  }

  private void runScenario(ScenarioPreset preset) {
    startScenario(preset, advancedOptionsPane.snapshot(), null);
  }

  private void startScenario(
      ScenarioPreset preset,
      AdvancedOptionsSnapshot options,
      Runnable completionCallback) {
    Objects.requireNonNull(preset, "preset");
    Objects.requireNonNull(options, "options");

    if (currentTask != null && currentTask.isRunning()) {
      statusLabel.setText("A scenario is already running; please wait");
      return;
    }

    afterScenarioCallback = completionCallback;
    lastScenarioResult = null;
    lastScenarioException = null;

    scenarioDescription.setText(preset.getDescription());
    securityContent.setText(SecurityExplanations.forPreset(preset));
    logEntries.clear();
    if (!logFilterGroup.getToggles().isEmpty()) {
      logFilterGroup.selectToggle(logFilterGroup.getToggles().get(0));
    }
    clearSummary();
    clearDataGroups();
    clearIssuerTab();
    resetStepper();
    lastReport = null;
    lastReportPath = null;
    copyCliButton.setDisable(true);
    copySessionInfoButton.setDisable(true);
    exportButton.setDisable(true);
    runDoc9303Button.setDisable(true);
    runAllButton.setDisable(true);
    statusLabel.setText("Running " + preset.getName() + "...");

    Path reportPath = buildReportPath(preset.getName());

    UiScenarioListener listener = new UiScenarioListener();
    currentTask = runner.createTask(preset, options, reportPath, listener, lastIssuerResult);
    currentTask.setOnSucceeded(e -> handleCompletion(currentTask.getValue()));
    currentTask.setOnFailed(e -> handleFailure(preset.getName(), currentTask.getException()));
    currentTask.setOnCancelled(e -> {
      statusLabel.setText("Cancelled");
      finishScenario();
    });

    Thread thread = new Thread(currentTask, "scenario-runner");
    thread.setDaemon(true);
    thread.start();
  }

  private void runAllScenarios() {
    if (batchRunState != null) {
      statusLabel.setText("Already running all tests");
      return;
    }
    if (currentTask != null && currentTask.isRunning()) {
      statusLabel.setText("Finish current scenario before running all tests");
      return;
    }

    List<ScenarioPreset> presets = new ArrayList<>(ScenarioPresets.all());
    if (presets.isEmpty()) {
      statusLabel.setText("No scenarios available to run");
      return;
    }

    AdvancedOptionsSnapshot options = advancedOptionsPane.snapshot();
    batchRunState = new BatchRunState(presets, options);
    if (scenarioButtonsBox != null) {
      scenarioButtonsBox.setDisable(true);
    }
    runDoc9303Button.setDisable(true);
    runAllButton.setDisable(true);
    statusLabel.setText("Running all tests...");
    runNextScenarioInBatch();
  }

  private void runNextScenarioInBatch() {
    if (batchRunState == null) {
      return;
    }
    if (batchRunState.index >= batchRunState.presets.size()) {
      finishBatchRun();
      return;
    }

    ScenarioPreset preset = batchRunState.presets.get(batchRunState.index);
    startScenario(preset, batchRunState.options, () -> {
      String summary = buildBatchSummary(preset);
      batchRunState.summaries.add(summary);
      batchRunState.index++;
      runNextScenarioInBatch();
    });
  }

  private void finishBatchRun() {
    if (batchRunState == null) {
      return;
    }
    boolean clipboardSuccess = false;
    Path summaryPath = null;
    if (!batchRunState.summaries.isEmpty()) {
      String joinedSummaries = joinBatchSummaries(batchRunState.summaries);
      clipboardSuccess = copyBatchSummariesToClipboard(joinedSummaries);
      summaryPath = writeBatchSummariesToFile(joinedSummaries);
    }
    if (scenarioButtonsBox != null) {
      scenarioButtonsBox.setDisable(false);
    }
    runAllButton.setDisable(false);
    runDoc9303Button.setDisable(false);
    if (summaryPath != null) {
      String message = clipboardSuccess
          ? "Completed all tests; summary copied to clipboard and saved to " + summaryPath
          : "Completed all tests; summary saved to " + summaryPath;
      statusLabel.setText(message);
    } else if (clipboardSuccess) {
      statusLabel.setText("Completed all tests; summary copied to clipboard");
    } else {
      statusLabel.setText("Completed all tests");
    }
    addLogEntry(SimLogCategory.GENERAL, "UI", "All scenario tests finished");
    batchRunState = null;
  }

  private String buildBatchSummary(ScenarioPreset preset) {
    String newline = System.lineSeparator();
    StringBuilder sb = new StringBuilder();
    sb.append("Scenario: ").append(preset.getName()).append(newline);
    sb.append("Explanation: ").append(preset.getDescription()).append(newline);

    if (lastScenarioResult != null) {
      if (lastScenarioResult.isSuccess()) {
        sb.append("Outcome: Success").append(newline);
        sb.append(buildSessionInfoText("  ")).append(newline);
      } else {
        sb.append("Outcome: Failed");
        if (lastScenarioResult.getFailedStep() != null) {
          sb.append(" at ").append(lastScenarioResult.getFailedStep());
        }
        sb.append(" (exit code ").append(lastScenarioResult.getExitCode()).append(")").append(newline);
        if (!lastScenarioResult.getCommands().isEmpty()) {
          sb.append("  Commands executed:").append(newline);
          for (String cmd : lastScenarioResult.getCommands()) {
            sb.append("    $").append(' ').append(cmd).append(newline);
          }
        }
        sb.append(buildSessionInfoText("  ")).append(newline);
      }
    } else if (lastScenarioException != null) {
      sb.append("Outcome: Error - ")
          .append(lastScenarioException.getClass().getSimpleName())
          .append(": ")
          .append(lastScenarioException.getMessage())
          .append(newline);
      sb.append(buildSessionInfoText("  ")).append(newline);
    } else {
      sb.append("Outcome: Cancelled").append(newline);
      sb.append(buildSessionInfoText("  ")).append(newline);
    }

    return sb.toString().stripTrailing();
  }

  private String joinBatchSummaries(List<String> summaries) {
    String newline = System.lineSeparator();
    return String.join(newline + newline, summaries);
  }

  private boolean copyBatchSummariesToClipboard(String joined) {
    try {
      ClipboardContent content = new ClipboardContent();
      content.putString(joined);
      Clipboard.getSystemClipboard().setContent(content);
      return true;
    } catch (RuntimeException ex) {
      addLogEntry(
          SimLogCategory.GENERAL,
          "UI",
          "Unable to copy batch summary to clipboard: " + ex.getMessage());
      return false;
    }
  }

  private Path writeBatchSummariesToFile(String joined) {
    Path directory = Paths.get("target", "ui-session");
    try {
      Files.createDirectories(directory);
      String fileName = "batch-summary-" + REPORT_TIMESTAMP.format(LocalDateTime.now()) + ".txt";
      Path destination = directory.resolve(fileName);
      Files.writeString(
          destination,
          joined,
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING,
          StandardOpenOption.WRITE);
      return destination;
    } catch (IOException ex) {
      addLogEntry(
          SimLogCategory.GENERAL,
          "UI",
          "Unable to write batch summary to file: " + ex.getMessage());
      return null;
    }
  }

  private void handleCompletion(ScenarioResult result) {
    lastScenarioResult = result;
    lastScenarioException = null;

    lastCommands = result.getCommands();
    copyCliButton.setDisable(lastCommands.isEmpty());
    lastReportPath = result.getReportPath();
    lastIssuerResult = result.getIssuerResult().orElse(null);
    updateIssuerTab(lastIssuerResult);
    updateCardDetailsTab(null, lastIssuerResult);

    if (!result.isSuccess()) {
      String failureMsg = "Scenario failed";
      if (result.getFailedStep() != null) {
        failureMsg += " at " + result.getFailedStep();
      }
      failureMsg += " (exit code " + result.getExitCode() + ")";
      statusLabel.setText(failureMsg);
      exportButton.setDisable(true);
      copySessionInfoButton.setDisable(false);
      finishScenario();
      return;
    }

    statusLabel.setText("Completed successfully");

    SessionReport report = result.getReport();
    if (report == null) {
      report = lastReport;
    }
    if (report != null) {
      SessionReportViewData viewData = SessionReportParser.fromReport(report);
      if (viewData != null) {
        updateSummary(viewData);
        updateDataGroups(viewData);
        updateCardDetailsTab(viewData, lastIssuerResult);
      }
      lastReport = report;
      exportButton.setDisable(false);
      copySessionInfoButton.setDisable(false);
    } else {
      try {
        SessionReportViewData viewData = SessionReportParser.parse(result.getReportPath());
        if (viewData != null) {
          updateSummary(viewData);
          updateDataGroups(viewData);
          updateCardDetailsTab(viewData, lastIssuerResult);
          exportButton.setDisable(false);
          copySessionInfoButton.setDisable(false);
        } else {
          statusLabel.setText("Completed (no report found)");
          exportButton.setDisable(true);
          copySessionInfoButton.setDisable(false);
        }
      } catch (Exception ex) {
        statusLabel.setText("Completed (report parse error)");
        addLogEntry(SimLogCategory.GENERAL, "UI", "Failed to parse report: " + ex.getMessage());
        exportButton.setDisable(true);
        copySessionInfoButton.setDisable(false);
      }
    }

    finishScenario();
  }

  private void handleFailure(String scenarioName, Throwable throwable) {
    lastScenarioResult = null;
    lastScenarioException = throwable;

    lastCommands = List.of();
    copyCliButton.setDisable(true);
    exportButton.setDisable(true);
    statusLabel.setText("Error running " + scenarioName + "); see log.");
    addLogEntry(SimLogCategory.GENERAL, "UI", throwable.getClass().getSimpleName() + ": " + throwable.getMessage());
    copySessionInfoButton.setDisable(false);
    lastIssuerResult = null;
    clearIssuerTab();
    clearCardDetailsTab();
    finishScenario();
  }

  private void finishScenario() {
    currentTask = null;

    Runnable callback = afterScenarioCallback;
    afterScenarioCallback = null;
    if (callback != null) {
      callback.run();
    }

    if (batchRunState == null) {
      runAllButton.setDisable(false);
      runDoc9303Button.setDisable(false);
      if (scenarioButtonsBox != null) {
        scenarioButtonsBox.setDisable(false);
      }
    }
  }

  private Callback<ListView<LogEntry>, ListCell<LogEntry>> createLogCellFactory() {
    return list -> new ListCell<>() {
      @Override
      protected void updateItem(LogEntry entry, boolean empty) {
        super.updateItem(entry, empty);
        if (empty || entry == null) {
          setText(null);
        } else {
          setText(formatLogEntry(entry));
        }
      }
    };
  }

  private void addLogEntry(SimLogCategory category, String source, String message) {
    LogEntry entry = new LogEntry(category, source, message);
    logEntries.add(entry);
    if (logEntries.size() > MAX_LOG_ENTRIES) {
      logEntries.remove(0);
    }
    if (!logEntries.isEmpty()) {
      logListView.scrollTo(logEntries.size() - 1);
    }
  }

  private void updateSummary(SessionReportViewData data) {
    verdictValue.setText(orDefault(data.getPassiveAuthVerdict()));
    String smMode = data.getSecureMessagingMode();
    if (smMode == null || smMode.isBlank()) {
      smModeValue.setText("—");
    } else {
      smModeValue.setText(smMode);
    }
    paceValue.setText(String.format("Attempted: %s | Established: %s",
        yesNo(data.isPaceAttempted()), yesNo(data.isPaceEstablished())));
    caValue.setText("Established: " + yesNo(data.isCaEstablished()));
    aaValue.setText(buildActiveAuthSummary(data));
    terminalAuthValue.setText(buildTerminalAuthSummary(data));
  }

  private void updateDataGroups(SessionReportViewData data) {
    List<String> labels = new ArrayList<>();
    for (Integer dg : data.getPresentDataGroups()) {
      labels.add("DG" + dg);
    }
    dgListView.getItems().setAll(labels);
    dg3ReadableValue.setText(yesNo(data.isDg3Readable()));
    dg4ReadableValue.setText(yesNo(data.isDg4Readable()));
  }

  private void clearSummary() {
    verdictValue.setText("—");
    smModeValue.setText("—");
    paceValue.setText("—");
    caValue.setText("—");
    aaValue.setText("—");
    terminalAuthValue.setText("—");
  }

  private void clearDataGroups() {
    dgListView.getItems().clear();
    dg3ReadableValue.setText("—");
    dg4ReadableValue.setText("—");
  }

  private void resetStepper() {
    for (SimPhase phase : phaseOrder) {
      Label label = phaseLabels.get(phase);
      if (label != null) {
        label.setText(formatPhaseLabel(phase, "○"));
      }
    }
    currentPhase = SimPhase.CONNECTING;
  }

  private void updatePhaseIndicator(SimPhase phase, String detail) {
    if (phase == SimPhase.FAILED) {
      Label label = phaseLabels.get(currentPhase);
      if (label != null) {
        label.setText(formatPhaseLabel(currentPhase, "✕"));
      }
      if (detail != null && !detail.isBlank()) {
        statusLabel.setText(detail);
      }
      return;
    }

    int phaseIndex = phaseOrder.indexOf(phase);
    if (phaseIndex < 0) {
      return;
    }

    currentPhase = phase;
    for (int i = 0; i < phaseOrder.size(); i++) {
      SimPhase iter = phaseOrder.get(i);
      Label label = phaseLabels.get(iter);
      if (label == null) {
        continue;
      }
      if (i < phaseIndex) {
        label.setText(formatPhaseLabel(iter, "✓"));
      } else if (i == phaseIndex) {
        label.setText(formatPhaseLabel(iter, phase == SimPhase.COMPLETE ? "✓" : "●"));
      } else {
        label.setText(formatPhaseLabel(iter, "○"));
      }
    }

    if (detail != null && !detail.isBlank()) {
      statusLabel.setText(detail);
    }
  }

  private void copyLastCommands() {
    if (lastCommands.isEmpty()) {
      return;
    }
    ClipboardContent content = new ClipboardContent();
    content.putString(String.join(System.lineSeparator(), lastCommands));
    Clipboard.getSystemClipboard().setContent(content);
    statusLabel.setText("CLI copied to clipboard");
  }

  private void copySessionInfo() {
    String summary = buildSessionInfoText("");
    ClipboardContent content = new ClipboardContent();
    content.putString(summary);
    Clipboard.getSystemClipboard().setContent(content);
    statusLabel.setText("Session info copied to clipboard");
  }

  private String buildSessionInfoText(String indent) {
    String newline = System.lineSeparator();
    String baseIndent = indent == null ? "" : indent;
    String levelOne = baseIndent + "  ";
    String levelTwo = levelOne + "  ";

    StringBuilder sb = new StringBuilder();

    sb.append(baseIndent).append("Summary").append(newline);
    sb.append(levelOne).append("Passive Auth verdict: ").append(verdictValue.getText()).append(newline);
    sb.append(levelOne).append("Secure messaging: ").append(smModeValue.getText()).append(newline);
    sb.append(levelOne).append("PACE: ").append(paceValue.getText()).append(newline);
    sb.append(levelOne).append("Chip Authentication: ").append(caValue.getText()).append(newline);
    sb.append(levelOne).append("Active Authentication: ").append(aaValue.getText()).append(newline);
    sb.append(levelOne).append("Terminal Authentication: ").append(terminalAuthValue.getText())
        .append(newline).append(newline);

    sb.append(baseIndent).append("Data Groups").append(newline);
    if (dgListView.getItems().isEmpty()) {
      sb.append(levelOne).append("(none)").append(newline);
    } else {
      for (String dg : dgListView.getItems()) {
        sb.append(levelOne).append(dg).append(newline);
      }
    }
    sb.append(levelOne).append("DG3 readable: ").append(dg3ReadableValue.getText()).append(newline);
    sb.append(levelOne).append("DG4 readable: ").append(dg4ReadableValue.getText()).append(newline).append(newline);

    if (lastIssuerResult != null) {
      sb.append(baseIndent).append("Issuer Output").append(newline);
      Path issuerOutput = lastIssuerResult.getOutputDirectory().toAbsolutePath();
      sb.append(levelOne).append("Output directory: ").append(issuerOutput).append(newline);
      Path manifestPath = lastIssuerResult.getManifestPath();
      sb.append(levelOne)
          .append("Manifest: ")
          .append(manifestPath != null ? manifestPath.toAbsolutePath() : "(not generated)")
          .append(newline);
      sb.append(levelOne).append("Lifecycle targets:");
      List<String> lifecycleTargets = lastIssuerResult.getJob().getLifecycleTargets();
      if (lifecycleTargets == null || lifecycleTargets.isEmpty()) {
        sb.append(' ').append("(none)").append(newline);
      } else {
        sb.append(newline);
        for (String target : lifecycleTargets) {
          sb.append(levelTwo).append(target).append(newline);
        }
      }
      Path csca = issuerOutput.resolve("CSCA.cer");
      if (Files.exists(csca)) {
        sb.append(levelOne).append("CSCA anchor: ").append(csca.toAbsolutePath()).append(newline);
      }
      Path dsc = issuerOutput.resolve("DSC.cer");
      if (Files.exists(dsc)) {
        sb.append(levelOne).append("DSC cert: ").append(dsc.toAbsolutePath()).append(newline);
      }
      lastIssuerResult.getPassiveAuthenticationResult().ifPresentOrElse(pa -> {
        sb.append(levelOne).append("Passive Authentication verdict: ")
            .append(pa.verdict()).append(newline);
        sb.append(levelOne).append("Digest algorithm: ")
            .append(orDefault(pa.getDigestAlgorithm())).append(newline);
        sb.append(levelOne).append("Bad data groups: ")
            .append(formatDataGroupList(pa.getBadDataGroups())).append(newline);
        sb.append(levelOne).append("Missing data groups: ")
            .append(formatDataGroupList(pa.getMissingDataGroups())).append(newline);
        sb.append(levelOne).append("Locked data groups: ")
            .append(formatDataGroupList(pa.getLockedDataGroups())).append(newline);
        List<String> trustIssues = pa.getTrustStoreIssues();
        if (trustIssues == null || trustIssues.isEmpty()) {
          sb.append(levelOne).append("Trust store issues: (none)").append(newline);
        } else {
          sb.append(levelOne).append("Trust store issues:").append(newline);
          for (String issue : trustIssues) {
            sb.append(levelTwo).append(issue).append(newline);
          }
        }
      }, () -> sb.append(levelOne).append("Passive Authentication verdict: (not run)").append(newline));
      lastIssuerResult.getFacePreviewPath().ifPresentOrElse(path ->
              sb.append(levelOne).append("Face preview: ").append(path.toAbsolutePath()).append(newline),
          () -> sb.append(levelOne).append("Face preview: (not generated)").append(newline));
      sb.append(newline);
    }

    sb.append(baseIndent).append("Technical Log").append(newline);
    if (logEntries.isEmpty()) {
      sb.append(levelOne).append("(no entries)").append(newline);
    } else {
      for (LogEntry entry : logEntries) {
        sb.append(levelOne).append(formatLogEntry(entry)).append(newline);
      }
    }
    sb.append(newline);

    sb.append(baseIndent).append("Security Explained").append(newline);
    String securityText = securityContent.getText();
    if (securityText == null || securityText.isBlank()) {
      sb.append(levelOne).append("(no details available)").append(newline);
    } else {
      for (String line : securityText.split("\r?\n")) {
        sb.append(levelOne).append(line).append(newline);
      }
    }

    return sb.toString();
  }

  private String buildActiveAuthSummary(SessionReportViewData data) {
    if (data == null) {
      return "—";
    }
    return String.format(
        "Enabled: %s | Supported: %s | Verified: %s | Algorithm: %s",
        yesNo(data.isActiveAuthEnabled()),
        yesNo(data.isActiveAuthSupported()),
        yesNo(data.isActiveAuthVerified()),
        orDefault(data.getActiveAuthAlgorithm()));
  }

  private String buildTerminalAuthSummary(SessionReportViewData data) {
    if (data == null) {
      return "—";
    }
    String rightsSummary = formatTerminalAuthRights(data.getTerminalAuthRole(), data.getTerminalAuthRights());
    String warningsSummary = formatTerminalAuthWarnings(data.getTerminalAuthWarnings());
    return String.format(
        "Attempted: %s | Succeeded: %s | DG3 unlocked: %s | DG4 unlocked: %s | Rights: %s | Warnings: %s",
        yesNo(data.isTerminalAuthAttempted()),
        yesNo(data.isTerminalAuthSucceeded()),
        yesNo(data.isTerminalAuthDg3Unlocked()),
        yesNo(data.isTerminalAuthDg4Unlocked()),
        rightsSummary,
        warningsSummary);
  }

  private String formatTerminalAuthRights(String role, String rights) {
    String normalizedRights = normalizeTerminalAuthRights(rights);
    if (role != null && !role.isBlank()) {
      if (normalizedRights == null) {
        return role;
      }
      return role + '(' + normalizedRights + ')';
    }
    return normalizedRights != null ? normalizedRights : "—";
  }

  private String normalizeTerminalAuthRights(String rights) {
    if (rights == null || rights.isBlank()) {
      return null;
    }
    String value = rights;
    if (value.startsWith("READ_ACCESS_")) {
      value = value.substring("READ_ACCESS_".length());
    }
    if ("NONE".equalsIgnoreCase(value)) {
      return "none";
    }
    value = value.replace("_AND_", " & ");
    value = value.replace('_', ' ');
    return value;
  }

  private String formatTerminalAuthWarnings(List<String> warnings) {
    if (warnings == null || warnings.isEmpty()) {
      return "none";
    }
    return String.join("; ", warnings);
  }

  private Path buildReportPath(String scenarioName) {
    String safeName = scenarioName.toLowerCase()
        .replaceAll("[^a-z0-9]+", "-")
        .replaceAll("-+", "-")
        .replaceAll("^-|-$", "");
    String fileName = safeName + "-" + REPORT_TIMESTAMP.format(LocalDateTime.now()) + ".json";
    return Paths.get("target", "ui-session", fileName);
  }

  private void exportSession() {
    if (lastReport == null && (lastReportPath == null || !Files.exists(lastReportPath))) {
      statusLabel.setText("No session to export yet");
      return;
    }

    DirectoryChooser chooser = new DirectoryChooser();
    chooser.setTitle("Export session");
    File chosen = chooser.showDialog(primaryStage);
    if (chosen == null) {
      return;
    }

    Path targetDir = chosen.toPath();
    String timestamp = REPORT_TIMESTAMP.format(LocalDateTime.now());
    Path jsonPath = targetDir.resolve("session-report-" + timestamp + ".json");
    Path logPath = targetDir.resolve("session-log-" + timestamp + ".txt");
    Path cliPath = targetDir.resolve("session-cli-" + timestamp + ".txt");

    try {
      Files.createDirectories(targetDir);
      if (lastReport != null) {
        lastReport.write(jsonPath);
      } else if (lastReportPath != null && Files.exists(lastReportPath)) {
        Files.copy(lastReportPath, jsonPath, StandardCopyOption.REPLACE_EXISTING);
      }

      StringBuilder logBuilder = new StringBuilder();
      for (LogEntry entry : logEntries) {
        logBuilder.append(formatLogEntry(entry)).append(System.lineSeparator());
      }
      Files.writeString(logPath, logBuilder.toString(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

      if (!lastCommands.isEmpty()) {
        Files.writeString(
            cliPath,
            String.join(System.lineSeparator(), lastCommands),
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING);
      }

      if (lastIssuerResult != null) {
        copyIssuerArtifacts(lastIssuerResult, targetDir);
      }

      statusLabel.setText("Exported session to " + targetDir.toAbsolutePath());
      addLogEntry(SimLogCategory.GENERAL, "UI", "Session exported to " + targetDir.toAbsolutePath());
    } catch (IOException e) {
      statusLabel.setText("Failed to export session");
      addLogEntry(SimLogCategory.GENERAL, "UI", "Export failed: " + e.getMessage());
    }
  }

  private static String formatPhaseLabel(SimPhase phase, String indicator) {
    return indicator + " " + phaseDisplayName(phase);
  }

  private static String phaseDisplayName(SimPhase phase) {
    String name = phase.name().toLowerCase().replace('_', ' ');
    return Character.toUpperCase(name.charAt(0)) + name.substring(1);
  }

  private String formatLogEntry(LogEntry entry) {
    StringBuilder sb = new StringBuilder();
    sb.append('[').append(entry.getCategory().name()).append(']');
    if (entry.getSource() != null && !entry.getSource().isBlank()) {
      sb.append(' ').append('[').append(entry.getSource()).append(']');
    }
    sb.append(' ').append(entry.getMessage());
    return sb.toString();
  }

  private static void addSummaryRow(GridPane grid, int row, String labelText, Label value) {
    Label label = new Label(labelText);
    GridPane.setRowIndex(label, row);
    GridPane.setColumnIndex(label, 0);
    GridPane.setRowIndex(value, row);
    GridPane.setColumnIndex(value, 1);
    grid.getChildren().addAll(label, value);
  }

  private static GridPane createComparisonGrid() {
    GridPane grid = new GridPane();
    grid.setHgap(12);
    grid.setVgap(8);
    return grid;
  }

  private static void addComparisonHeaders(GridPane grid) {
    Label fieldHeader = new Label("Field");
    fieldHeader.getStyleClass().add("summary-label");
    grid.add(fieldHeader, 0, 0);
    Label cardHeader = new Label("On-card (Issuer)");
    cardHeader.getStyleClass().add("summary-label");
    grid.add(cardHeader, 1, 0);
    Label terminalHeader = new Label("Terminal (Reader)");
    terminalHeader.getStyleClass().add("summary-label");
    grid.add(terminalHeader, 2, 0);
  }

  private static void addComparisonRow(GridPane grid, int row, String labelText, Label cardValue, Label terminalValue) {
    Label label = new Label(labelText);
    grid.add(label, 0, row);
    grid.add(cardValue, 1, row);
    grid.add(terminalValue, 2, row);
  }

  private static Label valueLabel() {
    Label label = new Label("—");
    label.getStyleClass().add("value-label");
    return label;
  }

  private static Label multilineValueLabel() {
    Label label = valueLabel();
    label.setWrapText(true);
    label.setMaxWidth(Double.MAX_VALUE);
    return label;
  }

  private static ImageView createPreviewImageView(double fitWidth) {
    ImageView view = new ImageView();
    view.setPreserveRatio(true);
    view.setSmooth(true);
    view.setFitWidth(fitWidth);
    return view;
  }

  private static String yesNo(boolean value) {
    return value ? "Yes" : "No";
  }

  private static String orDefault(String value) {
    return (value == null || value.isBlank()) ? "—" : value;
  }

  private void loadFacePreviewImage(Path path, ImageView target, String logSource) {
    if (path == null) {
      target.setImage(null);
      return;
    }

    Path absolute = path.toAbsolutePath();
    if (!Files.exists(absolute)) {
      target.setImage(null);
      logFacePreviewIssue(logSource, "Face preview not found at " + absolute);
      return;
    }

    target.setImage(null);
    double width = target.getFitWidth();
    Image image;
    try {
      image = new Image(absolute.toUri().toString(), width > 0 ? width : 0, 0, true, true, true);
    } catch (Exception ex) {
      logFacePreviewIssue(logSource, "Unable to load face preview image: " + ex.getMessage());
      return;
    }

    if (image.isError()) {
      Throwable exception = image.getException();
      logFacePreviewIssue(
          logSource,
          "Unable to load face preview image: " + (exception != null ? exception.getMessage() : "unknown error"));
      return;
    }

    if (!image.isBackgroundLoading() || image.getProgress() >= 1.0) {
      target.setImage(image);
    } else {
      image.progressProperty().addListener((obs, oldValue, newValue) -> {
        if (newValue != null && newValue.doubleValue() >= 1.0 && !image.isError()) {
          Platform.runLater(() -> target.setImage(image));
        }
      });
    }

    image.exceptionProperty().addListener((obs, oldEx, newEx) -> {
      if (newEx != null) {
        Platform.runLater(() -> {
          target.setImage(null);
          logFacePreviewIssue(logSource, "Unable to load face preview image: " + newEx.getMessage());
        });
      }
    });
  }

  private void loadFacePreviewImage(String pathString, ImageView target, String logSource) {
    if (pathString == null || pathString.isBlank()) {
      target.setImage(null);
      return;
    }
    try {
      loadFacePreviewImage(Paths.get(pathString), target, logSource);
    } catch (InvalidPathException ex) {
      target.setImage(null);
      logFacePreviewIssue(logSource, "Invalid face preview path: " + pathString);
    }
  }

  private void logFacePreviewIssue(String logSource, String message) {
    if (message == null || message.isBlank()) {
      return;
    }
    Runnable task = () -> addLogEntry(SimLogCategory.GENERAL, logSource, message);
    if (Platform.isFxApplicationThread()) {
      task.run();
    } else {
      Platform.runLater(task);
    }
  }

  private static String trimToNull(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }

  private void showAlert(Alert.AlertType type, String title, String message) {
    Alert alert = new Alert(type);
    alert.initOwner(primaryStage);
    alert.setTitle(title);
    alert.setHeaderText(title);
    alert.setContentText(message);
    alert.showAndWait();
  }

  private SessionReportViewData.MrzSummary buildMrzSummary(RealPassportSnapshot data) {
    String documentNumber = data.documentNumber();
    String dateOfBirth = data.dateOfBirth();
    String dateOfExpiry = data.dateOfExpiry();
    String issuingState = null;
    String primaryIdentifier = null;
    String secondaryIdentifier = null;
    String nationality = data.nationality();

    String mrz = data.mrz();
    if (mrz != null && !mrz.isBlank()) {
      String[] lines = mrz.split("\r?\n");
      if (lines.length > 0) {
        String line1 = lines[0];
        if (line1.length() >= 5) {
          issuingState = sanitizeMrzComponent(line1.substring(2, 5));
          String names = line1.length() > 5 ? line1.substring(5) : "";
          String[] parts = names.split("<<");
          if (parts.length > 0) {
            primaryIdentifier = sanitizeMrzComponent(parts[0]);
          }
          if (parts.length > 1) {
            secondaryIdentifier = sanitizeMrzComponent(parts[1]);
          }
        }
      }
    }

    if (primaryIdentifier == null || primaryIdentifier.isBlank()) {
      primaryIdentifier = sanitizeMrzComponent(data.fullName());
    }

    return new SessionReportViewData.MrzSummary(
        documentNumber,
        dateOfBirth,
        dateOfExpiry,
        primaryIdentifier,
        secondaryIdentifier,
        issuingState,
        nationality);
  }

  private static String sanitizeMrzComponent(String value) {
    if (value == null) {
      return null;
    }
    String cleaned = value.replace('<', ' ').trim();
    return cleaned.replaceAll(" +", " ");
  }

  private static String facePreviewExtension(String mime) {
    if (mime == null || mime.isBlank()) {
      return "bin";
    }
    String normalized = mime.toLowerCase(Locale.ROOT);
    switch (normalized) {
      case "image/jpeg":
      case "image/jpg":
        return "jpg";
      case "image/png":
        return "png";
      case "image/jp2":
        return "jp2";
      case "image/x-wsq":
      case "image/wsq":
        return "wsq";
      default:
        return "bin";
    }
  }

  private void clearIssuerTab() {
    issuerOutputDirectoryValue.setText("—");
    issuerManifestValue.setText("(not generated)");
    issuerLifecycleValue.setText("(none)");
    issuerCscaValue.setText("(not exported)");
    issuerDscValue.setText("(not exported)");
    issuerPassiveAuthVerdictValue.setText("—");
    issuerPassiveAuthDigestValue.setText("—");
    issuerPassiveAuthDataGroupsValue.setText("Bad: (none)\nMissing: (none)\nLocked: (none)");
    issuerPassiveAuthTrustIssuesValue.setText("(none)");
    issuerFaceSourceValue.setText("(default synthetic)");
    issuerFacePreviewPathValue.setText("(not generated)");
    issuerFacePreviewImage.setImage(null);
    if (issuerTab != null) {
      issuerTab.setDisable(true);
    }
    if (resultTabs != null && issuerTab != null
        && resultTabs.getSelectionModel().getSelectedItem() == issuerTab) {
      resultTabs.getSelectionModel().selectFirst();
    }
  }

  private void clearCardDetailsTab() {
    cardPortraitImage.setImage(null);
    terminalFacePreviewImage.setImage(null);

    cardMrzDocumentNumberValue.setText(ISSUER_PLACEHOLDER);
    cardMrzIssuingStateValue.setText(ISSUER_PLACEHOLDER);
    cardMrzNationalityValue.setText(ISSUER_PLACEHOLDER);
    cardMrzDateOfBirthValue.setText(ISSUER_PLACEHOLDER);
    cardMrzDateOfExpiryValue.setText(ISSUER_PLACEHOLDER);
    cardMrzPrimaryIdentifierValue.setText(ISSUER_PLACEHOLDER);
    cardMrzSecondaryIdentifierValue.setText(ISSUER_PLACEHOLDER);
    cardTransportValue.setText(ISSUER_PLACEHOLDER);
    cardSecureMessagingModeValue.setText(ISSUER_PLACEHOLDER);
    cardPaceProfilesValue.setText(ISSUER_PLACEHOLDER);
    cardChipAuthProfileValue.setText(ISSUER_PLACEHOLDER);
    cardActiveAuthProfileValue.setText(ISSUER_PLACEHOLDER);
    cardDigestAlgorithmValue.setText(ISSUER_PLACEHOLDER);
    cardProvisionedDataGroupsValue.setText(ISSUER_PLACEHOLDER);
    cardPaSignerValue.setText(ISSUER_PLACEHOLDER);
    cardPaChainValue.setText(ISSUER_PLACEHOLDER);

    terminalMrzDocumentNumberValue.setText(READER_PLACEHOLDER);
    terminalMrzIssuingStateValue.setText(READER_PLACEHOLDER);
    terminalMrzNationalityValue.setText(READER_PLACEHOLDER);
    terminalMrzDateOfBirthValue.setText(READER_PLACEHOLDER);
    terminalMrzDateOfExpiryValue.setText(READER_PLACEHOLDER);
    terminalMrzPrimaryIdentifierValue.setText(READER_PLACEHOLDER);
    terminalMrzSecondaryIdentifierValue.setText(READER_PLACEHOLDER);
    terminalTransportValue.setText(READER_PLACEHOLDER);
    terminalSecureMessagingModeValue.setText(READER_PLACEHOLDER);
    terminalPaceStatusValue.setText(READER_PLACEHOLDER);
    terminalChipAuthStatusValue.setText(READER_PLACEHOLDER);
    terminalActiveAuthStatusValue.setText(READER_PLACEHOLDER);
    terminalDigestAlgorithmValue.setText(READER_PLACEHOLDER);
    terminalPaDataGroupsValue.setText(READER_PLACEHOLDER);
    terminalPaSignerValue.setText(READER_PLACEHOLDER);
    terminalPaChainValue.setText(READER_PLACEHOLDER);

    if (cardDetailsTab != null) {
      cardDetailsTab.setDisable(true);
      if (resultTabs != null && resultTabs.getSelectionModel().getSelectedItem() == cardDetailsTab) {
        resultTabs.getSelectionModel().selectFirst();
      }
    }
  }

  private void updateIssuerTab(IssuerSimulator.Result issuerResult) {
    if (issuerResult == null) {
      clearIssuerTab();
      return;
    }

    issuerOutputDirectoryValue.setText(issuerResult.getOutputDirectory().toAbsolutePath().toString());
    Path manifestPath = issuerResult.getManifestPath();
    issuerManifestValue.setText(manifestPath != null
        ? manifestPath.toAbsolutePath().toString()
        : "(not generated)");
    issuerLifecycleValue.setText(formatStringList(issuerResult.getJob().getLifecycleTargets()));

    Path csca = issuerResult.getOutputDirectory().resolve("CSCA.cer");
    issuerCscaValue.setText(Files.exists(csca) ? csca.toAbsolutePath().toString() : "(not exported)");

    Path dsc = issuerResult.getOutputDirectory().resolve("DSC.cer");
    issuerDscValue.setText(Files.exists(dsc) ? dsc.toAbsolutePath().toString() : "(not exported)");

    issuerResult.getPassiveAuthenticationResult().ifPresentOrElse(pa -> {
      issuerPassiveAuthVerdictValue.setText(pa.verdict());
      issuerPassiveAuthDigestValue.setText(orDefault(pa.getDigestAlgorithm()));
      issuerPassiveAuthDataGroupsValue.setText(String.format(
          "Bad: %s\nMissing: %s\nLocked: %s",
          formatDataGroupList(pa.getBadDataGroups()),
          formatDataGroupList(pa.getMissingDataGroups()),
          formatDataGroupList(pa.getLockedDataGroups())));
      issuerPassiveAuthTrustIssuesValue.setText(formatStringList(pa.getTrustStoreIssues()));
    }, () -> {
      issuerPassiveAuthVerdictValue.setText("(not run)");
      issuerPassiveAuthDigestValue.setText("—");
      issuerPassiveAuthDataGroupsValue.setText("Bad: (none)\nMissing: (none)\nLocked: (none)");
      issuerPassiveAuthTrustIssuesValue.setText("(none)");
    });

    PersonalizationJob.BiometricSource faceSource = issuerResult.getJob().getFaceSource();
    if (faceSource != null) {
      if (faceSource.getPath() != null) {
        issuerFaceSourceValue.setText(faceSource.getPath().toAbsolutePath().toString());
      } else if (faceSource.getWidth() != null && faceSource.getHeight() != null) {
        issuerFaceSourceValue.setText(String.format(
            "Synthetic %dx%d", faceSource.getWidth(), faceSource.getHeight()));
      } else {
        issuerFaceSourceValue.setText("(synthetic)");
      }
    } else {
      issuerFaceSourceValue.setText("(default synthetic)");
    }

    issuerResult.getFacePreviewPath().ifPresentOrElse(path -> {
      issuerFacePreviewPathValue.setText(path.toAbsolutePath().toString());
      loadFacePreviewImage(path, issuerFacePreviewImage, "Issuer");
    }, () -> {
      issuerFacePreviewPathValue.setText("(not generated)");
      issuerFacePreviewImage.setImage(null);
    });

    if (issuerTab != null) {
      issuerTab.setDisable(false);
    }
    if (resultTabs != null && issuerTab != null) {
      resultTabs.getSelectionModel().select(issuerTab);
    }
  }

  private void updateCardDetailsTab(SessionReportViewData readerData, IssuerSimulator.Result issuerResult) {
    boolean hasIssuer = issuerResult != null;
    String issuerPreviewPath = null;
    if (hasIssuer) {
      PersonalizationJob job = issuerResult.getJob();
      MRZInfo mrz = job != null ? job.getMrzInfo() : null;
      cardMrzDocumentNumberValue.setText(orDefault(mrz != null ? mrz.getDocumentNumber() : null));
      cardMrzIssuingStateValue.setText(orDefault(mrz != null ? mrz.getIssuingState() : null));
      cardMrzNationalityValue.setText(orDefault(mrz != null ? mrz.getNationality() : null));
      cardMrzDateOfBirthValue.setText(orDefault(mrz != null ? mrz.getDateOfBirth() : null));
      cardMrzDateOfExpiryValue.setText(orDefault(mrz != null ? mrz.getDateOfExpiry() : null));
      cardMrzPrimaryIdentifierValue.setText(orDefault(mrz != null ? mrz.getPrimaryIdentifier() : null));
      cardMrzSecondaryIdentifierValue.setText(orDefault(mrz != null ? mrz.getSecondaryIdentifier() : null));
      cardTransportValue.setText("—");
      cardSecureMessagingModeValue.setText("—");
      cardPaceProfilesValue.setText(formatStringList(job.getPaceOids()));
      cardChipAuthProfileValue.setText(orDefault(job.getChipAuthenticationCurve()));
      cardActiveAuthProfileValue.setText(formatActiveAuthProfile(job));
      cardDigestAlgorithmValue.setText(orDefault(job.getDigestAlgorithm()));
      cardProvisionedDataGroupsValue.setText(formatDataGroupCollection(job.getEnabledDataGroups()));
      cardPaSignerValue.setText("—");
      cardPaChainValue.setText("—");
      issuerPreviewPath = issuerResult.getFacePreviewPath()
          .map(path -> path.toAbsolutePath().toString())
          .orElse(null);
    } else {
      cardMrzDocumentNumberValue.setText(ISSUER_PLACEHOLDER);
      cardMrzIssuingStateValue.setText(ISSUER_PLACEHOLDER);
      cardMrzNationalityValue.setText(ISSUER_PLACEHOLDER);
      cardMrzDateOfBirthValue.setText(ISSUER_PLACEHOLDER);
      cardMrzDateOfExpiryValue.setText(ISSUER_PLACEHOLDER);
      cardMrzPrimaryIdentifierValue.setText(ISSUER_PLACEHOLDER);
      cardMrzSecondaryIdentifierValue.setText(ISSUER_PLACEHOLDER);
      cardTransportValue.setText(ISSUER_PLACEHOLDER);
      cardSecureMessagingModeValue.setText(ISSUER_PLACEHOLDER);
      cardPaceProfilesValue.setText(ISSUER_PLACEHOLDER);
      cardChipAuthProfileValue.setText(ISSUER_PLACEHOLDER);
      cardActiveAuthProfileValue.setText(ISSUER_PLACEHOLDER);
      cardDigestAlgorithmValue.setText(ISSUER_PLACEHOLDER);
      cardProvisionedDataGroupsValue.setText(ISSUER_PLACEHOLDER);
      cardPaSignerValue.setText(ISSUER_PLACEHOLDER);
      cardPaChainValue.setText(ISSUER_PLACEHOLDER);
    }

    String terminalPreviewPath = null;
    if (readerData != null) {
      SessionReportViewData.MrzSummary mrz = readerData.getMrzSummary();
      if (mrz != null) {
        terminalMrzDocumentNumberValue.setText(orDefault(mrz.getDocumentNumber()));
        terminalMrzIssuingStateValue.setText(orDefault(mrz.getIssuingState()));
        terminalMrzNationalityValue.setText(orDefault(mrz.getNationality()));
        terminalMrzDateOfBirthValue.setText(orDefault(mrz.getDateOfBirth()));
        terminalMrzDateOfExpiryValue.setText(orDefault(mrz.getDateOfExpiry()));
        terminalMrzPrimaryIdentifierValue.setText(orDefault(mrz.getPrimaryIdentifier()));
        terminalMrzSecondaryIdentifierValue.setText(orDefault(mrz.getSecondaryIdentifier()));
      } else {
        terminalMrzDocumentNumberValue.setText(DG1_NOT_READ_PLACEHOLDER);
        terminalMrzIssuingStateValue.setText(DG1_NOT_READ_PLACEHOLDER);
        terminalMrzNationalityValue.setText(DG1_NOT_READ_PLACEHOLDER);
        terminalMrzDateOfBirthValue.setText(DG1_NOT_READ_PLACEHOLDER);
        terminalMrzDateOfExpiryValue.setText(DG1_NOT_READ_PLACEHOLDER);
        terminalMrzPrimaryIdentifierValue.setText(DG1_NOT_READ_PLACEHOLDER);
        terminalMrzSecondaryIdentifierValue.setText(DG1_NOT_READ_PLACEHOLDER);
      }
      terminalTransportValue.setText(orDefault(readerData.getTransport()));
      terminalSecureMessagingModeValue.setText(orDefault(readerData.getSecureMessagingMode()));
      terminalPaceStatusValue.setText(String.format("Attempted: %s | Established: %s",
          yesNo(readerData.isPaceAttempted()), yesNo(readerData.isPaceEstablished())));
      terminalChipAuthStatusValue.setText("Established: " + yesNo(readerData.isCaEstablished()));
      terminalActiveAuthStatusValue.setText(buildActiveAuthSummary(readerData));
      terminalDigestAlgorithmValue.setText(orDefault(readerData.getPassiveAuthAlgorithm()));
      terminalPaDataGroupsValue.setText(String.format(
          "OK: %s%nBad: %s%nMissing: %s%nLocked: %s",
          formatDataGroupList(readerData.getPassiveAuthOkDataGroups()),
          formatDataGroupList(readerData.getPassiveAuthBadDataGroups()),
          formatDataGroupList(readerData.getPassiveAuthMissingDataGroups()),
          formatDataGroupList(readerData.getPassiveAuthLockedDataGroups())));
      terminalPaSignerValue.setText(orDefault(readerData.getPassiveAuthSigner()));
      terminalPaChainValue.setText(orDefault(readerData.getPassiveAuthChainStatus()));
      terminalPreviewPath = readerData.getDg2PreviewPath();
      if (issuerPreviewPath == null) {
        issuerPreviewPath = readerData.getIssuerPreviewPath();
      }
    } else {
      terminalMrzDocumentNumberValue.setText(READER_PLACEHOLDER);
      terminalMrzIssuingStateValue.setText(READER_PLACEHOLDER);
      terminalMrzNationalityValue.setText(READER_PLACEHOLDER);
      terminalMrzDateOfBirthValue.setText(READER_PLACEHOLDER);
      terminalMrzDateOfExpiryValue.setText(READER_PLACEHOLDER);
      terminalMrzPrimaryIdentifierValue.setText(READER_PLACEHOLDER);
      terminalMrzSecondaryIdentifierValue.setText(READER_PLACEHOLDER);
      terminalTransportValue.setText(READER_PLACEHOLDER);
      terminalSecureMessagingModeValue.setText(READER_PLACEHOLDER);
      terminalPaceStatusValue.setText(READER_PLACEHOLDER);
      terminalChipAuthStatusValue.setText(READER_PLACEHOLDER);
      terminalActiveAuthStatusValue.setText(READER_PLACEHOLDER);
      terminalDigestAlgorithmValue.setText(READER_PLACEHOLDER);
      terminalPaDataGroupsValue.setText(READER_PLACEHOLDER);
      terminalPaSignerValue.setText(READER_PLACEHOLDER);
      terminalPaChainValue.setText(READER_PLACEHOLDER);
    }

    loadFacePreviewImage(issuerPreviewPath, cardPortraitImage, "Issuer");
    loadFacePreviewImage(terminalPreviewPath, terminalFacePreviewImage, "Terminal");

    if (cardDetailsTab != null) {
      boolean enable = hasIssuer || readerData != null;
      cardDetailsTab.setDisable(!enable);
      if (!enable && resultTabs != null && resultTabs.getSelectionModel().getSelectedItem() == cardDetailsTab) {
        resultTabs.getSelectionModel().selectFirst();
      }
    }
  }

  private void copyIssuerArtifacts(IssuerSimulator.Result issuerResult, Path targetDir) throws IOException {
    List<Path> sources = new ArrayList<>();
    Path manifest = issuerResult.getManifestPath();
    if (manifest != null && Files.exists(manifest)) {
      sources.add(manifest);
    }
    Path csca = issuerResult.getOutputDirectory().resolve("CSCA.cer");
    if (Files.exists(csca)) {
      sources.add(csca);
    }
    Path dsc = issuerResult.getOutputDirectory().resolve("DSC.cer");
    if (Files.exists(dsc)) {
      sources.add(dsc);
    }
    if (sources.isEmpty()) {
      return;
    }
    Path issuerDir = targetDir.resolve("issuer");
    Files.createDirectories(issuerDir);
    for (Path source : sources) {
      Files.copy(source, issuerDir.resolve(source.getFileName()), StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static String formatStringList(List<String> values) {
    if (values == null || values.isEmpty()) {
      return "(none)";
    }
    return String.join(System.lineSeparator(), values);
  }

  private static String formatDataGroupList(List<Integer> dataGroups) {
    if (dataGroups == null || dataGroups.isEmpty()) {
      return "(none)";
    }
    List<String> formatted = new ArrayList<>();
    for (Integer dg : dataGroups) {
      if (dg == null) {
        continue;
      }
      formatted.add("DG" + dg);
    }
    if (formatted.isEmpty()) {
      return "(none)";
    }
    return String.join(", ", formatted);
  }

  private static String formatDataGroupCollection(Collection<Integer> dataGroups) {
    if (dataGroups == null || dataGroups.isEmpty()) {
      return "(none)";
    }
    List<Integer> sorted = new ArrayList<>();
    for (Integer dg : dataGroups) {
      if (dg != null) {
        sorted.add(dg);
      }
    }
    if (sorted.isEmpty()) {
      return "(none)";
    }
    Collections.sort(sorted);
    return formatDataGroupList(sorted);
  }

  private static String formatActiveAuthProfile(PersonalizationJob job) {
    if (job == null) {
      return "—";
    }
    int size = job.getAaKeySize();
    if (size > 0) {
      return size + "-bit key";
    }
    return "—";
  }

  private static final class BatchRunState {
    final List<ScenarioPreset> presets;
    final AdvancedOptionsSnapshot options;
    final List<String> summaries = new ArrayList<>();
    int index;

    BatchRunState(List<ScenarioPreset> presets, AdvancedOptionsSnapshot options) {
      this.presets = List.copyOf(presets);
      this.options = options;
      this.index = 0;
    }
  }

  private final class UiScenarioListener implements ScenarioExecutionListener {
    @Override
    public void onLog(SimLogCategory category, String source, String message) {
      Platform.runLater(() -> addLogEntry(category, source, message));
    }

    @Override
    public void onPhase(SimPhase phase, String detail) {
      Platform.runLater(() -> updatePhaseIndicator(phase, detail));
    }

    @Override
    public void onReport(SessionReport report) {
      Platform.runLater(() -> lastReport = report);
    }
  }

  public static void main(String[] args) {
    launch(args);
  }
}
