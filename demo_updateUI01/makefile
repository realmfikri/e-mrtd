
all:

build:
	mvn clean package dependency:copy-dependencies 

# Detect platform-specific classpath separator.
ifeq ($(OS),Windows_NT)
CP_SEP := ;
else
CP_SEP := :
endif

CLASSPATH := target/demo-1.0-SNAPSHOT.jar$(CP_SEP)target/dependency/*

run:
	java -cp "$(CLASSPATH)" com.example.UniversalPassportReader
