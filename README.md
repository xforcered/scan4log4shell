# scan4log4shell
A Burp Pro extension that adds log4shell checks to Burp Scanner, written by Daniel Crowley of IBM X-Force Red.

# Installation
To install this extension, you'll need the Jython standalone jar file required to use Python-based Burp extensions. You can get it at [https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.2/jython-standalone-2.7.2.jar](https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.2/jython-standalone-2.7.2.jar).

Use the Burp Extender tab to point to the `scan4log4shell.py` file after downloading it from this repository.

# Usage
To use this extension, use Burp Scanner normally. A check for log4shell will be added to the battery of executed tests.

If you would like to scan ONLY for log4shell, you can disable all checks except for "Extension-generated checks" in the scan configuration.
