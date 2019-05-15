/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.model;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.stream.Collectors;

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
public class SignatureFile implements ISignatureFile {
    private static final ILogger logger = GlobalLog.getLogger(SignatureFile.class);

    private Map<String, List<MethodSignature>> allTightSignatures = new HashMap<>();
    private Map<String, List<MethodSignature>> allLooseSignatures = new HashMap<>();
    private Map<String, List<MethodSignature>> allSignaturesByClassname = new HashMap<>();
    private Map<String, List<MethodSignature>> allMetaByClassname = new HashMap<>();
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
                ml = MethodSignature.parse(line, false);
                if(ml == null) {
                    logger.warn("Invalid signature line: %s", line);
                    continue;
                }
                saveValue(allMetaByClassname, ml.getCname(), ml);
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
        saveValue(allTightSignatures, sig.getMhash_tight(), sig);
        saveValue(allLooseSignatures, sig.getMhash_loose(), sig);
        saveValue(allSignaturesByClassname, sig.getCname(), sig);
    }

    private static void saveValue(Map<String, List<MethodSignature>> map, String key, MethodSignature value) {
        List<MethodSignature> val = map.get(key);
        if(val == null) {
            val = new ArrayList<>();
            map.put(key, val);
        }
        val.add(value);
    }

    /**
     * Get all information related to tight method signatures.
     * 
     * @return a Map (Key: the tight method signature. Value: a list of string array {libname,
     *         cname, mname, shorty})
     * @deprecated require whole file to be loaded: use {@link #getTightSignatures(String)} instead
     */
    @Deprecated
    public Map<String, List<MethodSignature>> getAllTightSignatures() {
        return allTightSignatures;
    }

    @Override
    public List<MethodSignature> getTightSignatures(String hashcode) {
        return allTightSignatures.get(hashcode);
    }

    public long getTightSignaturesSize() {
        return allTightSignatures.size();
    }

    /**
     * Get Signatures that have a tight/loose reference
     * 
     * @return
     */
    public long getSignaturesSize() {
        long sz = 0;
        for(List<MethodSignature> e: getAllTightSignatures().values()) {
            sz += e.size();
        }
        return sz;
    }

    @Override
    public List<MethodSignature> getLooseSignatures(String hashcode) {
        return allLooseSignatures.get(hashcode);
    }

    public long getLooseSignaturesSize() {
        return allLooseSignatures.size();
    }

    /**
     * Get all information related to loose method signatures.
     * 
     * @return a Map (Key: the loose method signature. Value: a list of string array {libname,
     *         cname, mname, shorty})
     * @deprecated require whole file to be loaded: use {@link #getLooseSignatures(String)} instead
     */
    @Deprecated
    public Map<String, List<MethodSignature>> getAllLooseSignatures() {
        return allLooseSignatures;
    }

    @Override
    public Map<String, LibraryInfo> getAllLibraryInfos() {
        return allLibraryInfos;
    }

    @Override
    public int getAllSignatureCount() {
        return allSignatureCount;
    }

    @Override
    public List<MethodSignature> getSignaturesForClassname(String className, boolean exactName) {
        List<MethodSignature> compatibleSignatures = new ArrayList<>();
        if(exactName) {
            List<MethodSignature> list = allSignaturesByClassname.get(className);
            if(list != null) {
                compatibleSignatures.addAll(list);
            }
            return compatibleSignatures;
        }
        for(Entry<String, List<MethodSignature>> entry: allSignaturesByClassname.entrySet()) {
            if(entry.getKey().startsWith(className)) {
                compatibleSignatures.addAll(entry.getValue());
            }
        }
        return compatibleSignatures;
    }

    @Override
    public List<MethodSignature> getParent(String className) {
        List<MethodSignature> compatibleSignatures = new ArrayList<>();
        List<MethodSignature> list = allMetaByClassname.get(className);
        if(list != null) {
            compatibleSignatures.addAll(list);
            compatibleSignatures = compatibleSignatures.stream().filter(m -> m.getMname().equals("<parent>"))
                    .collect(Collectors.toList());
        }
        return compatibleSignatures;
    }

    public static boolean populate(File sigFile, Map<String, Set<String>> allTightHashcodes,
            Map<String, Set<String>> allLooseHashcodes, Map<String, Set<String>> allClasses) {
        List<String> lines = IO.readLinesSafe(sigFile, Charset.forName("UTF-8"));
        if(lines == null) {
            return false;
        }

        for(String line: lines) {
            line = line.trim();
            if(!MethodSignature.isSignatureLine(line)) {
                continue;
            }

            String[] subLines = MethodSignature.parseNative(line);
            if(subLines == null) {
                logger.warn("Invalid parameter signature line: " + line + " in file " + sigFile);
                continue;
            }

            String mhash_tight = MethodSignature.getTightSignature(subLines);
            if(mhash_tight != null && !mhash_tight.isEmpty()) {
                Set<String> files = allTightHashcodes.get(mhash_tight);
                if(files == null) {
                    files = new LinkedHashSet<>();
                    allTightHashcodes.put(mhash_tight, files);
                }
                files.add(sigFile.getAbsolutePath());
            }
            String mhash_loose = MethodSignature.getLooseSignature(subLines);
            if(mhash_loose != null && !mhash_loose.isEmpty()) {
                Set<String> files = allLooseHashcodes.get(mhash_loose);
                if(files == null) {
                    files = new LinkedHashSet<>();
                    allLooseHashcodes.put(mhash_loose, files);
                }
                files.add(sigFile.getAbsolutePath());
            }
            String className = MethodSignature.getClassname(subLines);
            if(className != null && !className.isEmpty()) {
                Set<String> files = allClasses.get(className);
                if(files == null) {
                    files = new LinkedHashSet<>();
                    allClasses.put(className, files);
                }
                files.add(sigFile.getAbsolutePath());
            }
        }
        return true;
    }

    @Override
    public void close() throws IOException {

    }
}
