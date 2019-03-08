/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.model;

import java.io.File;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.pnfsoftware.jeb.util.encoding.Conversion;
import com.pnfsoftware.jeb.util.io.IO;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Represent a list of signatures. It may represent one file or several (depends on caller).
 * 
 * @author Ruoxiao Wang, Cedric Lucas
 *
 */
public class SignatureFile {
    private final ILogger logger = GlobalLog.getLogger(SignatureFile.class);

    private Map<String, List<String[]>> allTightSignatures = new HashMap<>();
    private Map<String, List<String[]>> allLooseSignatures = new HashMap<>();
    private Map<String, LibraryInfo> allLibraryInfos = new HashMap<>();
    private int allSignatureCount = 0;

    public boolean loadSignatures(File sigFile) {
        int version = 0;
        String libname = "Unknown library code";
        String author = "Unknown author";

        List<String> lines = IO.readLinesSafe(sigFile, Charset.forName("UTF-8"));
        if(lines == null) {
            return false;
        }

        List<MethodSignature> mllist = new ArrayList<>();
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

            MethodSignature ml = MethodSignature.parse(line);
            if(ml == null) {
                logger.warn("Invalid signature line: %s", line);
                continue;
            }

            mllist.add(ml);
            allLibraryInfos.put(ml.getCname(), libraryInfo);
            allSignatureCount++;
        }

        // store method signatures
        for(MethodSignature ml: mllist) {
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

    public Map<String, LibraryInfo> getAllLibraryInfos() {
        return allLibraryInfos;
    }

    public int getAllSignatureCount() {
        return allSignatureCount;
    }

}
