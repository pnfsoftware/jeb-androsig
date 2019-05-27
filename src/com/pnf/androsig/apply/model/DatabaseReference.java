/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.model;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import com.pnf.androsig.apply.matcher.DatabaseReferenceFile;
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

    /** file list containing a hashcode, with hashcode as key */
    private Map<String, Set<String>> allTightHashcodes = new HashMap<>();
    private Map<String, Set<String>> allLooseHashcodes = new HashMap<>();
    private Map<String, Set<String>> allClasses = new HashMap<>();

    private SignatureFileFactory signatureFileFactory = new SignatureFileFactory();

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
        Runtime rt = Runtime.getRuntime();
        long memused = rt.totalMemory() - rt.freeMemory();
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
            long newmemused = rt.totalMemory() - rt.freeMemory();
            if(newmemused - memused > 1_000_000_000L) {
                // Attempt gc before jeb asks for memory
                System.gc();
                memused = rt.totalMemory() - rt.freeMemory();
            }
        }
    }

    private boolean loadHashCodes(File sigFile) {
        return SignatureFileFactory.populate(sigFile, allTightHashcodes, allLooseHashcodes, allClasses);
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

    @SuppressWarnings("resource")
    public List<MethodSignature> getSignatureLines(String file, String hashcode, boolean tight) {
        ISignatureFile sigFile = signatureFileFactory.getSignatureFile(file);
        return tight ? sigFile.getTightSignatures(hashcode): sigFile.getLooseSignatures(hashcode);
    }

    @SuppressWarnings("resource")
    public List<MethodSignature> getSignaturesForClassname(String file, String className, boolean exactName) {
        ISignatureFile sigFile = signatureFileFactory.getSignatureFile(file);
        return sigFile.getSignaturesForClassname(className, exactName);
    }

    public List<MethodSignature> getSignaturesForClassname(DatabaseReferenceFile file, String className,
            boolean exactName) {
        List<MethodSignature> sigs = getSignaturesForClassname(file.file, className, exactName);
        Set<String> versions = file.versions.keySet();
        return sigs.stream().filter(m -> intersect(versions, m.getVersions())).collect(Collectors.toList());
    }

    private boolean intersect(Set<String> versions, String[] versions2) {
        if(versions2 == null || versions2.length == 0 || versions == null || versions.size() == 0) {
            return true;
        }
        for(String v: versions2) {
            if(versions.contains(v)) {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("resource")
    public Map<String, LibraryInfo> getAllLibraryInfos(String file) {
        ISignatureFile sigFile = signatureFileFactory.getSignatureFile(file);
        return sigFile.getAllLibraryInfos();
    }

    public Map<String, ISignatureFile> getLoadedSignatureFiles() {
        return signatureFileFactory.getLoadedSignatureFiles();
    }

    public void close() {
        signatureFileFactory.close();
    }

    @SuppressWarnings("resource")
    public List<MethodSignature> getParentForClassname(String file, String className) {
        ISignatureFile sigFile = signatureFileFactory.getSignatureFile(file);
        return sigFile.getParent(className);
    }

    public List<String> getClassList(String f) {
        List<String> classes = new ArrayList<>();
        for(Entry<String, Set<String>> class_: allClasses.entrySet()) {
            if(class_.getValue().contains(f)) {
                classes.add(class_.getKey());
            }
        }
        return classes;
    }

}
