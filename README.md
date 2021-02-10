# Androsig - Android Library Code Matching for JEB

## Introduction

The purpose of this plugin is to help deobfuscate obfuscated applications. Using our generic collection of signatures for common libraries, library code can be recognized; methods and classes can be renamed; package hierarchies can be rebuilt. 

Tutorials on how to use:

- [Post on Androidsig 1.0](https://www.pnfsoftware.com/blog/jeb-library-code-matching-for-android/) (important read)
- [Post on Androsig 1.1](https://www.pnfsoftware.com/blog/new-version-of-androsig)

Remember to download a [signatures bundle of common libraries](https://s3-us-west-2.amazonaws.com/jebdecompiler2/androsig_1.1_db_20190515.zip), as instructed in the tutorial linked.

## Building from Source

Use the provided build-xxx script to build both plugins (packaged in a single JAR); the version number 'x.y.z' is located in AndroSigCommon. Update the version number in the script file before building.

## Components

### Android Signature Generator plugin

This plugin is mainly for generating library signatures which are used to match obfuscated applications.

### Android Signature Recognizer plugin

Based on library signatures and through recognizer plugin, library code in obfuscated applications can be recognized.

## Getting Started

### Prerequisities

Simply drop plugin into [JEB_FOLDER]/coreplugins folder and restart JEB.

### Running Signature Generator plugin

1. In JEB, click `File -> Open` to open an android apk.
2. Select `File -> Engines -> Execute` and select the generator plugin.
3. Enter the library name (usually the same as application name) and click `OK`.
4. The signature file (.sig) will be generated in `[JEB_FOLDER]/coreplugins/android_sigs` folder.

### Running Signature Recognizer plugin

Please make sure all your signature files are in the `[JEB_FOLDER]/coreplugins/android_sigs` folder.

1. In JEB, click `File -> Open` to open an android apk.
2. Select `File -> Engines -> Execute` and select the Recognizer plugin.
3. Customize the matching parameters if need ba and click `OK`.
4. The signature file (.sig) will be generated in `[JEB_FOLDER]/coreplugins/android_sigs` folder.

## Result

After running signature recognizer plugin, two files will be generated in your TEMP folder:

* `androsig-mapping.txt`: a mapping file shows the original class, method names mapped to the obfuscated names.
* `androsig-report.txt`: provides the comprehensive information about the matching.

## Copyright and License

JEB Copyright PNF Software, Inc.

https://www.pnfsoftware.com

Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
