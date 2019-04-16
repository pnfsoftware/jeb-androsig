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
import java.util.Map.Entry;

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

    private Map<String, List<MethodSignature>> allTightSignatures = new HashMap<>();
    private Map<String, List<MethodSignature>> allLooseSignatures = new HashMap<>();
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
            storeMethodHash(ml);
        }
        return true;
    }

    private String checkMarker(String line, String marker) {
        if(line.startsWith(marker + "=")) {
            return line.substring(marker.length() + 1).trim();
        }
        return null;
    }

    private void storeMethodHash(MethodSignature sig) {
        if(!allTightSignatures.containsKey(sig.getMhash_tight())) {
            allTightSignatures.put(sig.getMhash_tight(), new ArrayList<>());
        }
        allTightSignatures.get(sig.getMhash_tight()).add(sig);
        if(!allLooseSignatures.containsKey(sig.getMhash_loose())) {
            allLooseSignatures.put(sig.getMhash_loose(), new ArrayList<>());
        }
        allLooseSignatures.get(sig.getMhash_loose()).add(sig);
    }

    /**
     * Get all information related to tight method signatures.
     * 
     * @return a Map (Key: the tight method signature. Value: a list of string array {libname,
     *         cname, mname, shorty})
     */
    public Map<String, List<MethodSignature>> getAllTightSignatures() {
        return allTightSignatures;
    }

    /**
     * Get all information related to loose method signatures.
     * 
     * @return a Map (Key: the loose method signature. Value: a list of string array {libname,
     *         cname, mname, shorty})
     */
    public Map<String, List<MethodSignature>> getAllLooseSignatures() {
        return allLooseSignatures;
    }

    public Map<String, LibraryInfo> getAllLibraryInfos() {
        return allLibraryInfos;
    }

    public int getAllSignatureCount() {
        return allSignatureCount;
    }

    public List<MethodSignature> getSignaturesForClassname(String className, boolean exactName) {
        List<MethodSignature> compatibleSignatures = new ArrayList<>();
        for(Entry<String, List<MethodSignature>> entry: allTightSignatures.entrySet()) {
            for(MethodSignature sig: entry.getValue()) {
                if((exactName && sig.getCname().equals(className))
                        || (!exactName && sig.getCname().startsWith(className))) {
                    compatibleSignatures.add(sig);
                }
            }
        }
        return compatibleSignatures;
    }
}
