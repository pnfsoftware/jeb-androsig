# **jeb2-androsig plugins** - ANDROID SIGNATURE MATCHING SYSTEM

## Introduction

The main function of the Dalvik library recognition plugins is to help deobfuscating obfuscated applications. Using our semi-generic collection of signatures for common libraries, library code can be recognized; methods and classes can be renamed; package hierarchies can be rebuilt. 

To be used with JEB v2.2.8. It will ship end of August.

For more information about the matching system, please see our **Blog**.

## Component

### Android Signature Generator plugin

This plugin is mainly for generating library signatures which are used to match obfuscated applications.

### Android Signature Recognizer plugin

Based on library signatures and through recognizer plugin, library code in obfuscated applications can be recognized.

## Getting Started

### Prerequisities

Simply drop plugin into [JEB_FOLDER]/coreplugins folder and restart JEB.

### Running Signature Generator plugin

1. In JEB2, click `File -> Open` to open an android apk.
2. Select `File -> Engines -> Execute` and select the generator plugin.
3. Enter the library name (usually the same as application name) and click `OK`.
4. The signature file (.sig) will be generated in `[JEB_FOLDER]/coreplugins/android_sigs` folder.

### Running Signature Recognizer plugin

Please make sure all your signature files are in the `[JEB_FOLDER]/coreplugins/android_sigs` folder.

1. In JEB2, click `File -> Open` to open an android apk.
2. Select `File -> Engines -> Execute` and select the Recognizer plugin.
3. Customize the matching parameters if need ba and click `OK`.
4. The signature file (.sig) will be generated in `[JEB_FOLDER]/coreplugins/android_sigs` folder.

## Result

After running signature recognizer plugin, two files will be generated on Desktop:

* `mapping.txt`: a mapping file shows the original class, method names mapped to the obfuscated names.
* `report.txt`: provides the comprehensive information about the matching.

## Copyright and License

JEB Copyright PNF Software, Inc.

*     https://www.pnfsoftware.com

Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

*     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.