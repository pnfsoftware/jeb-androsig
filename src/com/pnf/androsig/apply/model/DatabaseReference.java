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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.pnfsoftware.jeb.util.io.IO;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Reference Hashcode that are contained in android_sigs directory. It enables user to get the list
 * of files that defines a particular hashcode (tight or loose).
 * 
 * @author Ruoxiao Wang, Cedric Lucas
 *
 */
public class DatabaseReference {
    private final ILogger logger = GlobalLog.getLogger(DatabaseReference.class);

    private static final int LIMIT_LOAD = 200;

    /** file list containing a hashcode, with hashcode as key */
    private Map<String, Set<String>> allTightHashcodes = new HashMap<>();
    private Map<String, Set<String>> allLooseHashcodes = new HashMap<>();
    private Map<String, Set<String>> allClasses = new HashMap<>();
    /** sigLines, with filename as key */
    private Map<String, SignatureFile> sigLinePerFilename = new HashMap<>();
    private List<String> loadOrder = new ArrayList<>();

    private int allSignatureFileCount = 0;

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
            if(mhash_tight != null) {
                Set<String> files = allTightHashcodes.get(mhash_tight);
                if(files == null) {
                    files = new LinkedHashSet<>();
                    allTightHashcodes.put(mhash_tight, files);
                }
                files.add(sigFile.getAbsolutePath());
            }
            String mhash_loose = MethodSignature.getLooseSignature(subLines);
            if(mhash_loose != null) {
                Set<String> files = allLooseHashcodes.get(mhash_loose);
                if(files == null) {
                    files = new LinkedHashSet<>();
                    allLooseHashcodes.put(mhash_loose, files);
                }
                files.add(sigFile.getAbsolutePath());
            }
            String className = MethodSignature.getClassname(subLines);
            if(className != null) {
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

    /**
     * Get the number of signature files.
     * 
     * @return the number of signature files
     */
    public int getAllSignatureFileCount() {
        return allSignatureFileCount;
    }

    public List<String> getFilesContainingTightHashcode(String hashcode) {
        Set<String> res = allTightHashcodes.get(hashcode);
        return res == null ? null: new ArrayList<>(res);
    }

    public List<String> getFilesContainingLooseHashcode(String hashcode) {
        Set<String> res = allLooseHashcodes.get(hashcode);
        return res == null ? null: new ArrayList<>(res);
    }

    public List<String> getFilesContainingClass(String className) {
        Set<String> res = allClasses.get(className);
        return res == null ? null: new ArrayList<>(res);
    }

    public List<MethodSignature> getSignatureLines(String file, String hashcode, boolean tight) {
        SignatureFile sigFile = getSignatureFile(file);
        return tight ? sigFile.getAllTightSignatures().get(hashcode): sigFile.getAllLooseSignatures().get(hashcode);
    }

    public SignatureFile getSignatureFile(String file) {
        SignatureFile sigFile = sigLinePerFilename.get(file);
        if(sigFile == null) {
            if(sigLinePerFilename.size() >= LIMIT_LOAD) {
                // delete half
                int deleted = LIMIT_LOAD / 2;
                for(int i = 0; i < deleted; i++) {
                    sigLinePerFilename.remove(loadOrder.remove(0));
                }
            }
            sigFile = new SignatureFile();
            sigFile.loadSignatures(new File(file));
            sigLinePerFilename.put(file, sigFile);
            // logger.info("Load %s", file);
        }
        loadOrder.remove(file);
        loadOrder.add(file);
        return sigFile;
    }

    public Map<String, SignatureFile> getLoadedSignatureFiles() {
        return sigLinePerFilename;
    }
}
