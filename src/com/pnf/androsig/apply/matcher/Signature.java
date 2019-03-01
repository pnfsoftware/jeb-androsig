/*
 * JEB Copyright PNF Software, Inc.
 * 
 *     https://www.pnfsoftware.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.pnf.androsig.apply.matcher;

import java.io.File;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.LibraryInfo;
import com.pnf.androsig.apply.model.SigDefLine;
import com.pnf.androsig.common.SignatureHandler;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexCodeItem;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethodData;
import com.pnfsoftware.jeb.util.encoding.Conversion;
import com.pnfsoftware.jeb.util.io.IO;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * TODO This class will be removed<br>
 * The class contains all information about the signatures.
 * 
 * @author Ruoxiao Wang
 *
 */
class Signature implements ISignatureMetrics {
    private final ILogger logger = GlobalLog.getLogger(Signature.class);

    private Map<String, List<String[]>> allTightSignatures;
    private Map<String, List<String[]>> allLooseSignatures;

    private Map<String, LibraryInfo> allLibraryInfos;

    // Record
    private int allSignatureCount = 0;
    private int allUsedSignatureFileCount = 0;

    public Signature() {
        allTightSignatures = new HashMap<>();
        allLooseSignatures = new HashMap<>();

        allLibraryInfos = new HashMap<>();
    }

    /**
     * Get the number of signatures.
     * 
     * @return the number of signatures
     */
    public int getAllSignatureCount() {
        return allSignatureCount;
    }

    /**
     * Get the number of used signature files.
     * 
     * @return the number of used signature files
     */
    public int getAllUsedSignatureFileCount() {
        return allUsedSignatureFileCount;
    }

    /**
     * Get all information related to tight method signatures.
     * 
     * @return a Map (Key: the tight method signature. Value: a list of string array {libname,
     *         cname, mname, shorty})
     */
    public Map<String, List<String[]>> getAllTightSignatures() {
        return allTightSignatures;
    }

    /**
     * Get all information related to loose method signatures.
     * 
     * @return a Map (Key: the loose method signature. Value: a list of string array {libname,
     *         cname, mname, shorty})
     */
    public Map<String, List<String[]>> getAllLooseSignatures() {
        return allLooseSignatures;
    }

    /**
     * Get all library information.
     * 
     * @return a Map (Key: the class signature path. Value: LibraryInfo Object)
     */
    public Map<String, LibraryInfo> getAllLibraryInfos() {
        return allLibraryInfos;
    }

    /**
     * Load all signatures.
     * 
     * @param unit mandatory target unit
     */
    public void loadAllSignatures(IDexUnit unit, DatabaseReference ref) {
        // Store all used signature files
        logger.info("Used Sig Files storing start...");
        final long startTime = System.currentTimeMillis();
        Set<String> usedSigFiles = new HashSet<>();
        storeAllUsedSigFiles(unit, usedSigFiles, ref);
        final long endTime = System.currentTimeMillis();
        logger.info("Used Sig Files storing completed! (Execution Time: " + (endTime - startTime) / 1000 + "s)");

        // Load all signatures
        logger.info("Library signatures loading start...");
        final long startTime1 = System.currentTimeMillis();
        File f;
        for(String filePath: usedSigFiles) {
            f = new File(filePath);
            if(!loadSignatures(f)) {
                logger.error("Cannot load signatures files: %s", f);
            }
        }
        final long endTime1 = System.currentTimeMillis();
        logger.info("Library signatures loading completed! (Execution Time: " + (endTime1 - startTime1) / 1000 + "s)");
        allUsedSignatureFileCount = usedSigFiles.size();
        usedSigFiles.clear();
        long a = 0;
        for(List<String[]> e: allTightSignatures.values()) {
            a += e.size();
        }
        long b = 0;
        for(List<String[]> e: allLooseSignatures.values()) {
            b += e.size();
        }
        int allSigCount = allTightSignatures.size() + allLooseSignatures.size();
        long c = allSigCount == 0 ? -1: (a + b) / allSigCount;
        logger.info("Average candidates: " + c);

        logger.info("allTightSignatures map size: " + allTightSignatures.size());
        logger.info("candidates: " + a);
        logger.info("allLooseSignatures map size: " + allLooseSignatures.size());
        logger.info("candidates: " + b);
    }

    private boolean loadSignatures(File sigFile) {
        int version = 0;
        String libname = "Unknown library code";
        String author = "Unknown author";

        List<String> lines = IO.readLinesSafe(sigFile, Charset.forName("UTF-8"));
        if(lines == null) {
            return false;
        }

        List<SigDefLine> mllist = new ArrayList<>();
        // Store library information
        LibraryInfo libraryInfo = new LibraryInfo();

        for(String line: lines) {
            line = line.trim();
            if(line.isEmpty()) {
                continue;
            }

            if(line.startsWith(";")) {
                line = line.substring(1);

                String value = checkMarker(line, "version");
                if(value != null) {
                    version = Conversion.stringToInt(value);
                    libraryInfo.setVersion(version);
                }

                value = checkMarker(line, "libname");
                if(value != null) {
                    libname = value;
                    libraryInfo.setLibName(libname);
                }

                value = checkMarker(line, "author");
                if(value != null) {
                    author = value;
                    libraryInfo.setAuthor(author);
                }
                continue;
            }

            SigDefLine ml = new SigDefLine();
            ml = ml.parse(line);
            if(ml == null) {
                logger.warn("Invalid signature line: %s", line);
                continue;
            }

            mllist.add(ml);
            allLibraryInfos.put(ml.getCname(), libraryInfo);
            allSignatureCount++;
        }

        // store method signatures
        for(SigDefLine ml: mllist) {
            storeMethodHash(ml.getMhash_loose(), ml.getMhash_tight(), ml.getCname(), ml.getMname(), ml.getShorty(),
                    ml.getPrototype(), ml.getCaller());
        }
        return true;
    }

    private String checkMarker(String line, String marker) {
        if(line.startsWith(marker + "=")) {
            return line.substring(marker.length() + 1).trim();
        }
        return null;
    }

    private void storeMethodHash(String mhash_loose, String mhash_tight, String cname, String mname, String shorty,
            String prototype, String caller) {
        String[] sigs = new String[]{cname, mname, shorty, prototype, caller};
        if(!allTightSignatures.containsKey(mhash_tight)) {
            allTightSignatures.put(mhash_tight, new ArrayList<String[]>());
        }
        allTightSignatures.get(mhash_tight).add(sigs);
        if(!allLooseSignatures.containsKey(mhash_loose)) {
            allLooseSignatures.put(mhash_loose, new ArrayList<String[]>());
        }
        allLooseSignatures.get(mhash_loose).add(sigs);
    }

    private void storeAllUsedSigFiles(IDexUnit dex, Set<String> usedSigFiles, DatabaseReference ref) {
        List<? extends IDexClass> classes = dex.getClasses();
        if(classes == null || classes.size() == 0) {
            return;
        }
        for(IDexClass eClass: classes) {
            List<? extends IDexMethod> methods = eClass.getMethods();
            if(methods == null || methods.size() == 0) {
                continue;
            }
            for(IDexMethod eMethod: methods) {
                if(!eMethod.isInternal()) {
                    continue;
                }

                IDexMethodData md = eMethod.getData();
                if(md == null) {
                    continue;
                }
                IDexCodeItem ci = md.getCodeItem();
                if(ci == null) {
                    continue;
                }
                else {
                    boolean tightFlag = true; // Use tight sig
                    boolean looseFlag = true; // Use loose sig
                    String mhash_tight = SignatureHandler.generateTightHashcode(ci);
                    if(mhash_tight == null) {
                        tightFlag = false;
                    }
                    if(tightFlag) {
                        List<String> files = ref.getFilesContainingTightHashcode(mhash_tight);
                        if(files != null && !files.isEmpty()) {
                            usedSigFiles.add(files.get(files.size() - 1));
                            looseFlag = false;
                        }
                    }
                    if(looseFlag) {
                        String mhash_loose = SignatureHandler.generateLooseHashcode(ci);
                        if(mhash_loose == null) {
                            continue;
                        }
                        List<String> files = ref.getFilesContainingLooseHashcode(mhash_loose);
                        if(files != null && !files.isEmpty()) {
                            usedSigFiles.add(files.get(files.size() - 1));
                            looseFlag = false;
                        }
                    }
                }
            }
        }
    }
}
