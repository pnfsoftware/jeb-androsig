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

package com.pnf.androsig.apply.model;

import java.io.File;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
 * The class contains all information about the signatures.
 * 
 * @author Ruoxiao Wang
 *
 */
public class Signature {
    private final ILogger logger = GlobalLog.getLogger(Signature.class);

    private Map<String, String> allTightHashcodes;
    private Map<String, String> allLooseHashcodes;

    private Map<String, List<String[]>> allTightSignatures;
    private Map<String, List<String[]>> allLooseSignatures;
    
    private Map<String, LibraryInfo> allLibraryInfos;

    // Record
    private int allSignatureCount = 0;
    private int allSignatureFileCount = 0;
    private int allUsedSignatureFileCount = 0;

    public Signature() {
        allTightHashcodes = new HashMap<>();
        allLooseHashcodes = new HashMap<>();

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
     * Get the number of signature files.
     * 
     * @return the number of signature files
     */
    public int getAllSignatureFileCount() {
        return allSignatureFileCount;
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
     * Load all hashcodes from signature files.
     * 
     * @param sigFolder the signature folder
     */
    public void loadAllHashCodes(File sigFolder) {
        logger.info("Hashcodes loading start...");
        final long startTime = System.currentTimeMillis();
        loadAllHashCodesTemp(sigFolder);
        final long endTime = System.currentTimeMillis();
        logger.info("Hashcodes loading completed! (Execution Time: " + (endTime - startTime) / 1000 + "s)");
        logger.info("allTightHashcodes: " + allTightHashcodes.size());
        logger.info("allLooseHashcodes: " + allLooseHashcodes.size());
    }

    private void loadAllHashCodesTemp(File sigFolder) {
        for(File f: sigFolder.listFiles()) {
            if(f.isFile() && f.getName().endsWith(".sig")) {
                allSignatureFileCount++;
                if(!loadHashCodes(f)) {
                    logger.error("Cannot load signatures files: %s", f);
                }
            }
            else if(f.isDirectory()) {
                loadAllHashCodesTemp(f);
            }
        }
    }

    private boolean loadHashCodes(File sigFile) {
        List<String> lines = IO.readLines(sigFile, Charset.forName("UTF-8"));
        if(lines == null) {
            return false;
        }

        for(String line: lines) {
            line = line.trim();
            if(line.isEmpty() || line.startsWith(";")) {
                continue;
            }

            String[] subLines = line.trim().split(",");
            if(subLines.length != 8) {
                logger.info("Invalid parameter signature line");
                continue;
            }

            if(subLines[5] != null && !allTightHashcodes.containsKey(subLines[4])) {
                allTightHashcodes.put(subLines[5], sigFile.getAbsolutePath());
            }
            if(subLines[6] != null && !allLooseHashcodes.containsKey(subLines[5])) {
                allLooseHashcodes.put(subLines[6], sigFile.getAbsolutePath());
            }
        }
        return true;
    }

    /**
     * Load all signatures.
     * 
     * @param unit mandatory target unit
     */
    public void loadAllSignatures(IDexUnit unit) {
        // Store all used signature files
        logger.info("Used Sig Files storing start...");
        final long startTime = System.currentTimeMillis();
        Set<String> usedSigFiles = new HashSet<>();
        storeAllUsedSigFiles(unit, usedSigFiles);
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
        for(List<String[]> e : allTightSignatures.values()) {
            a += e.size();
        }
        long b = 0;
        for(List<String[]> e : allLooseSignatures.values()) {
            b += e.size();
        }
        long c = (a + b) / (allTightSignatures.size() + allLooseSignatures.size());
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
        
        List<String> lines = IO.readLines(sigFile, Charset.forName("UTF-8"));
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
            storeMethodHash(ml.getMhash_loose(), ml.getMhash_tight(), ml.getCname(), ml.getMname(), ml.getShorty(), ml.getPrototype(),
                    ml.getCaller());
        }
        return true;
    }
    
    private String checkMarker(String line, String marker) {
        if(line.startsWith(marker + "=")) {
            return line.substring(marker.length() + 1).trim();
        }
        return null;
    }

    private void storeMethodHash(String mhash_loose, String mhash_tight, String cname, String mname, String shorty, String prototype,
            String caller) {
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

    private void storeAllUsedSigFiles(IDexUnit dex, Set<String> usedSigFiles) {
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
                        if(allTightHashcodes.containsKey(mhash_tight)) {
                            usedSigFiles.add(allTightHashcodes.get(mhash_tight));
                            looseFlag = false;
                        }
                    }
                    if(looseFlag) {
                        String mhash_loose = SignatureHandler.generateLooseHashcode(ci);
                        if(mhash_loose == null) {
                            continue;
                        }
                        if(allLooseHashcodes.containsKey(mhash_loose)) {
                            usedSigFiles.add(allLooseHashcodes.get(mhash_loose));
                        }
                    }
                }
            }
        }
        allLooseHashcodes = null;
        allTightHashcodes = null;
    }
}
