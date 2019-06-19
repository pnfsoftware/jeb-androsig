/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.pnf.androsig.apply.model.DatabaseReference;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnf.androsig.apply.util.DexUtilLocal;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * Keep a library of files/versions used and try to get coherence with one version.
 * 
 * @author Cedric Lucas
 *
 */
public class FileMatches {
    private final ILogger logger = GlobalLog.getLogger(FileMatches.class);

    private Map<Integer, DatabaseReferenceFile> matchedClassesFile = new HashMap<>();

    /** Used files -> list of versions match (with occurrences) */
    private Map<String, DatabaseReferenceFile> usedSigFiles = new HashMap<>();

    // class index --- classPath_sig
    private Map<Integer, String> matchedClasses = new LinkedHashMap<>();

    // method index --- methodName_sig
    private Map<Integer, String> matchedMethods = new LinkedHashMap<>();
    private Map<Integer, MethodSignature> matchedSigMethods = new HashMap<>();

    public Set<String> getSignatureFileUsed() {
        return usedSigFiles.keySet();
    }

    public Set<Entry<String, DatabaseReferenceFile>> getSignatureFileEntrySet() {
        return usedSigFiles.entrySet();
    }

    public boolean isSignatureFileUsed(String f) {
        return usedSigFiles.containsKey(f);
    }

    public DatabaseReferenceFile getFromFilename(String file) {
        return usedSigFiles.get(file);
    }

    public DatabaseReferenceFile getFileFromClass(IDexUnit dex, IDexClass dexClass) {
        if(dexClass == null) {
            return null;
        }
        DatabaseReferenceFile refFile = getFileFromClassId(dexClass.getIndex());
        if(refFile == null) {
            String signature = dexClass.getSignature(true);
            if(DexUtilLocal.isInnerClass(signature)) {
                refFile = getFileFromClass(dex, DexUtilLocal.getParentClass(dex, signature));
                if(refFile != null) {
                    matchedClassesFile.put(dexClass.getIndex(), refFile);
                }
            }
        }
        return refFile;
    }

    public DatabaseReferenceFile getFileFromClassId(int index) {
        return matchedClassesFile.get(index);
    }

    public void addMatchedClassFiles(IDexClass dexClass, String file) {
        DatabaseReferenceFile refFile = usedSigFiles.get(file);
        if(refFile == null) {
            refFile = new DatabaseReferenceFile(file, null);
            usedSigFiles.put(file, refFile);
        }
        matchedClassesFile.put(dexClass.getIndex(), refFile);
    }

    public DatabaseReferenceFile removeClassFiles(IDexClass dexClass) {
        return matchedClassesFile.remove(dexClass.getIndex());
    }

    /**
     * Save and merge versions used for one file.
     * 
     * @param file
     * @param values
     * @return
     */
    public boolean saveFileVersions(String file, Collection<MethodSignature> values) {
        DatabaseReferenceFile refFile = usedSigFiles.get(file);
        if(refFile == null) {
            refFile = new DatabaseReferenceFile(file, null);
            usedSigFiles.put(file, refFile);
        }
        refFile.mergeVersions(values);
        return true;
    }

    public List<List<String>> getOrderedVersions(String f) {
        return getOrderedVersions(usedSigFiles.get(f));
    }

    public List<List<String>> getOrderedVersions(DatabaseReferenceFile refFile) {
        if(refFile == null) {
            return new ArrayList<>();
        }
        return refFile.getOrderedVersions();
    }


    public DatabaseReferenceFile getMatchedClassFile(IDexUnit dex, IDexClass cl, String className,
            DatabaseReference ref) {
        DatabaseReferenceFile refFile = getFileFromClass(dex, cl);
        if(refFile != null) {
            return refFile;
        }
        String f = null;
        List<String> fs = ref.getFilesContainingClass(className);
        if(fs == null || fs.isEmpty()) {
            return null;
        }
        if(fs.size() == 1) {
            f = fs.get(0);
            if(!usedSigFiles.containsKey(f)) {
                usedSigFiles.put(f, null);
            }
            addMatchedClassFiles(cl, f);
            return usedSigFiles.get(f);
        }
        List<String> candidates = new ArrayList<>();
        for(String cand: fs) {
            if(usedSigFiles.containsKey(cand)) {
                candidates.add(cand);
            }
        }
        if(candidates.isEmpty()) {
            return null;
        }
        if(candidates.size() == 1) {
            f = candidates.get(0);
            addMatchedClassFiles(cl, f);
            return usedSigFiles.get(f);
        }
        List<String> newcandidates = new ArrayList<>();
        int bestLevel = -1;
        for(String candidate: candidates) {
            int level = getLevel(ref, candidate, className);
            if(level >= 0) {
                if(bestLevel < 0) {
                    bestLevel = level;
                    newcandidates.add(candidate);
                }
                else if(level < bestLevel) {
                    newcandidates.clear();
                    bestLevel = level;
                    newcandidates.add(candidate);
                }
                else if(level == bestLevel) {
                    newcandidates.add(candidate);
                }
            }
        }
        if(newcandidates.size() == 1) {
            f = newcandidates.get(0);
            addMatchedClassFiles(cl, f);
            return usedSigFiles.get(f);
        }
        return null;// maybe duplicated, wait for other part to decide
    }

    private int getLevel(DatabaseReference ref, String f, String className) {
        List<MethodSignature> compatibleSignatures = ref.getSignaturesForClassname(f, className, true);
        DatabaseReferenceFile refFile = usedSigFiles.get(f);
        List<List<String>> preferedOrderList = refFile.getOrderedVersions();
        int level = 0;
        if(preferedOrderList.isEmpty()) {
            return level;
        }
        for(List<String> preferedOrder: preferedOrderList) {
            for(String prefered: preferedOrder) {
                for(MethodSignature sig: compatibleSignatures) {
                    String[] versionsArray = sig.getVersions();
                    if(versionsArray == null) {
                        return level;
                    }
                    if(Arrays.asList(versionsArray).contains(prefered)) {
                        return level;
                    }
                }
            }
            level++;
        }
        return -1;
    }

    public List<MethodSignature> getSignatureLines(DatabaseReference ref, String file, String hashcode, boolean tight) {
        if(!usedSigFiles.containsKey(file)) {
            return ref.getSignatureLines(file, hashcode, tight);
        }
        DatabaseReferenceFile refFile = usedSigFiles.get(file);
        return ref.getSignatureLines(refFile, hashcode, tight);
    }

    public void addMatchedClass(IDexClass cl, String classname, boolean safe) {
        if(matchedClasses.get(cl.getIndex()) != null) {
            logger.error("Conflict: Try to replace class %s", matchedClasses.get(cl.getIndex()));
            return;
        }
        if(matchedClasses.containsValue(classname)) {
            logger.error("Conflict: Try to bind class %s to %s which is already bind to ", classname,
                    cl.getSignature(false), cl.getSignature(true));
            return;
        }
        matchedClasses.put(cl.getIndex(), classname);
        if(!safe) {
            removeClassFiles(cl);
        }
    }

    public void removeMatchedClass(int index) {
        matchedClasses.remove(index);
        matchedClassesFile.remove(index);
    }

    public String getMatchedClass(IDexClass cl) {
        return getMatchedClass(cl.getIndex());
    }

    public String getMatchedClass(int index) {
        return matchedClasses.get(index);
    }

    public boolean containsMatchedClass(IDexClass cl) {
        return containsMatchedClass(cl.getIndex());
    }

    public boolean containsMatchedClass(int index) {
        return matchedClasses.containsKey(index);
    }

    public boolean containsMatchedClassValue(String className) {
        return matchedClasses.containsValue(className);
    }

    public Map<Integer, String> getMatchedClasses() {
        return matchedClasses;
    }

    public Set<Entry<Integer, String>> entrySetMatchedClasses() {
        return matchedClasses.entrySet();
    }

    public void addMatchedMethod(IDexMethod m, String methodName) {
        if(matchedMethods.get(m.getIndex()) != null) {
            logger.error("Conflict: Try to replace method %s", m);
            return;
        }
        matchedMethods.put(m.getIndex(), methodName);
    }

    public void addMatchedMethod(int index, MethodSignature sig) {
        if(matchedMethods.get(index) != null) {
            logger.error("Conflict: Try to replace method %s", index);
            return;
        }
        matchedMethods.put(index, sig.getMname());
        matchedSigMethods.put(index, sig);
    }

    public void bindMatchedSigMethod(IDexMethod eMethod, MethodSignature ms) {
        matchedSigMethods.put(eMethod.getIndex(), ms);
    }

    public String getMatchedMethod(IDexMethod m) {
        return getMatchedMethod(m.getIndex());
    }

    public String getMatchedMethod(int index) {
        return matchedMethods.get(index);
    }

    public MethodSignature getMatchedSigMethod(IDexMethod m) {
        return getMatchedSigMethod(m.getIndex());
    }

    public MethodSignature getMatchedSigMethod(int index) {
        return matchedSigMethods.get(index);
    }

    public boolean containsMatchedMethod(IDexMethod m) {
        return containsMatchedMethod(m.getIndex());
    }

    public boolean containsMatchedMethod(int index) {
        return matchedMethods.containsKey(index);
    }

    public void removeMatchedMethod(int index) {
        matchedMethods.remove(index);
        matchedSigMethods.remove(index);
    }

    public Map<Integer, String> getMatchedMethods() {
        return matchedMethods;
    }

    public Set<Entry<Integer, String>> entrySetMatchedMethods() {
        return matchedMethods.entrySet();
    }

    public Set<Entry<Integer, MethodSignature>> entrySetMatchedSigMethods() {
        return matchedSigMethods.entrySet();
    }

}
